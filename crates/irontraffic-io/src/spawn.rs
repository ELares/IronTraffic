// SPDX-License-Identifier: MIT OR Apache-2.0

//! Owned task spawning. Data-plane code must never call `tokio::spawn`; the
//! runtime a task lands on is an explicit argument, not a property of the
//! calling thread.

use std::future::Future;

use thiserror::Error;

/// A handle to a runtime that tasks may be spawned onto.
///
/// Data-plane code must never call `tokio::spawn`: the runtime a task lands on is
/// an explicit argument, not a property of the calling thread.
#[derive(Clone, Debug)]
pub struct Spawner(tokio::runtime::Handle);

impl Spawner {
    /// Wraps a runtime handle.
    #[must_use]
    pub fn from_handle(handle: tokio::runtime::Handle) -> Self {
        Self(handle)
    }

    /// The handle for the runtime driving the current thread.
    ///
    /// # Errors
    /// Returns [`NoRuntime`] when called from a thread with no runtime, instead of
    /// panicking the way `tokio::runtime::Handle::current` does.
    pub fn current() -> Result<Self, NoRuntime> {
        tokio::runtime::Handle::try_current()
            .map(Self)
            .map_err(|_| NoRuntime)
    }

    /// Spawns `fut` on this runtime.
    pub fn spawn<F>(&self, fut: F) -> TaskHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        TaskHandle {
            inner: Some(self.0.spawn(fut)),
        }
    }
}

/// No tokio runtime is driving the current thread.
#[derive(Debug, Error)]
#[error("no runtime is driving the current thread")]
pub struct NoRuntime;

/// An owned handle to a spawned task. Dropping it aborts the task.
#[must_use = "dropping a TaskHandle aborts the task; call detach() to keep it running"]
#[derive(Debug)]
pub struct TaskHandle<T> {
    inner: Option<tokio::task::JoinHandle<T>>,
}

impl<T> TaskHandle<T> {
    /// Lets the task keep running after this handle is dropped.
    pub fn detach(mut self) {
        // Take the inner handle so Drop sees None and does not abort.
        let _ = self.inner.take();
    }

    /// Requests cancellation. The task stops at its next await point.
    pub fn abort(&self) {
        if let Some(h) = self.inner.as_ref() {
            h.abort();
        }
    }

    /// Waits for the task to finish.
    ///
    /// # Errors
    /// Returns [`TaskError::Panicked`] if the task panicked (the payload is
    /// deliberately not propagated) or [`TaskError::Aborted`] if it was cancelled.
    pub async fn join(mut self) -> Result<T, TaskError> {
        // Await through `&mut` and only `take()` the handle out once the await
        // has resolved. `JoinHandle<T>` is `Unpin`, so `&mut JoinHandle<T>`
        // implements `Future` via the standard blanket impl for `&mut F where
        // F: Future + Unpin`.
        //
        // Taking the handle out BEFORE the await (as an earlier shape of this
        // function did) moves the `JoinHandle` out of `self`. If the `join()`
        // future is then itself dropped before it resolves, for example raced
        // against a deadline with `with_timeout`, the moved-out `JoinHandle`
        // drops too, and dropping a `JoinHandle` detaches the task rather than
        // aborting it. By that point `self.inner` was already `None`, so
        // `Drop` (the invariant-4 safety net) found nothing to abort either,
        // and the task ran on unowned. Keeping the handle in `self.inner` until
        // there is a result to return means a cancelled `join()` still leaves
        // `Some` behind for `Drop` to abort.
        let result = match self.inner.as_mut() {
            Some(h) => h.await,
            None => return Err(TaskError::Aborted), // unreachable: only detach/join take it
        };
        self.inner = None;
        match result {
            Ok(v) => Ok(v),
            Err(e) if e.is_cancelled() => Err(TaskError::Aborted),
            Err(_) => Err(TaskError::Panicked),
        }
    }
}

impl<T> Drop for TaskHandle<T> {
    fn drop(&mut self) {
        if let Some(h) = self.inner.as_ref() {
            h.abort();
        }
    }
}

/// Why a task did not produce a value.
#[derive(Debug, Error)]
pub enum TaskError {
    /// The task panicked. The payload is dropped rather than resumed.
    #[error("task panicked")]
    Panicked,
    /// The task was cancelled.
    #[error("task was aborted")]
    Aborted,
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    #[test]
    fn spawner_current_outside_runtime_is_err() {
        let result = thread::spawn(Spawner::current)
            .join()
            .expect("thread did not panic");
        assert!(matches!(result, Err(NoRuntime)));
    }
}
