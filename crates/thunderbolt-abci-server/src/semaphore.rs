use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

pub(crate) struct PermitPool {
    capacity: usize,
    available: Mutex<usize>,
    changed: Condvar,
    poisoned: AtomicBool,
}

impl PermitPool {
    pub(crate) fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            capacity,
            available: Mutex::new(capacity),
            changed: Condvar::new(),
            poisoned: AtomicBool::new(false),
        })
    }

    pub(crate) fn try_acquire(self: &Arc<Self>, amount: usize) -> Result<Option<Permit>, ()> {
        if amount == 0 || amount > self.capacity || self.poisoned.load(Ordering::Acquire) {
            return Err(());
        }
        let mut available = self.available.lock().map_err(|_| {
            self.mark_poisoned();
        })?;
        if *available < amount {
            return Ok(None);
        }
        *available -= amount;
        Ok(Some(Permit {
            pool: Arc::clone(self),
            amount,
        }))
    }

    pub(crate) fn acquire_until(
        self: &Arc<Self>,
        amount: usize,
        deadline: Instant,
        shutdown: &AtomicBool,
    ) -> Result<Option<Permit>, ()> {
        if amount == 0 || amount > self.capacity || self.poisoned.load(Ordering::Acquire) {
            return Err(());
        }
        let mut available = self.available.lock().map_err(|_| {
            self.mark_poisoned();
        })?;
        loop {
            if self.poisoned.load(Ordering::Acquire) {
                return Err(());
            }
            if shutdown.load(Ordering::Acquire) {
                return Ok(None);
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            if *available >= amount {
                *available -= amount;
                return Ok(Some(Permit {
                    pool: Arc::clone(self),
                    amount,
                }));
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Ok(None);
            };
            let (next, timeout) = self.changed.wait_timeout(available, remaining).map_err(|_| {
                self.mark_poisoned();
            })?;
            available = next;
            if timeout.timed_out() {
                return Ok(None);
            }
        }
    }

    pub(crate) fn wake_all(&self) {
        self.changed.notify_all();
    }

    fn mark_poisoned(&self) {
        self.poisoned.store(true, Ordering::Release);
        self.changed.notify_all();
    }

    #[cfg(test)]
    pub(crate) fn poison_for_test(&self) {
        self.mark_poisoned();
    }
}

pub(crate) struct Permit {
    pool: Arc<PermitPool>,
    amount: usize,
}

impl Drop for Permit {
    fn drop(&mut self) {
        if let Ok(mut available) = self.pool.available.lock() {
            match available.checked_add(self.amount) {
                Some(next) if next <= self.pool.capacity => {
                    *available = next;
                    self.pool.changed.notify_all();
                }
                _ => self.pool.mark_poisoned(),
            }
        } else {
            self.pool.mark_poisoned();
        }
    }
}
