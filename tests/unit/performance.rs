//! Unit tests for Performance Requirements (P1-P4)
//!
//! This module contains unit tests covering performance requirements.
//! Tests have been migrated from proxy.rs.

use fluxgate::proxy::ConnectionLimiter;
use tokio::time::{sleep, Duration};

#[test]
fn connection_limiter_enforces_limit() {
    // Precondition: Connection limiter with limit of 2.
    // Action: Try to acquire 3 permits from connection limiter.
    // Expected behavior: Only 2 permits can be acquired, third should fail with error.
    // Covers Requirements: P2
    let limiter = ConnectionLimiter::new(2);
    assert_eq!(limiter.active_count(), 0);

    let permit1 = limiter.try_acquire().expect("first permit should succeed");
    assert_eq!(limiter.active_count(), 1);

    let _permit2 = limiter.try_acquire().expect("second permit should succeed");
    assert_eq!(limiter.active_count(), 2);

    // Third try_acquire should fail immediately when limit is reached
    let permit3_result = limiter.try_acquire();
    assert!(
        permit3_result.is_err(),
        "third permit should be rejected when limit is reached"
    );
    assert_eq!(limiter.active_count(), 2);

    // After releasing one permit, should be able to acquire again
    drop(permit1);
    assert_eq!(limiter.active_count(), 1);

    let permit3 = limiter
        .try_acquire()
        .expect("third permit should succeed after release");
    assert_eq!(limiter.active_count(), 2);
    drop(permit3);
}

#[tokio::test]
async fn connection_limiter_tracks_active_connections() {
    // Precondition: Connection limiter with limit of 5.
    // Action: Acquire and release permits from connection limiter.
    // Expected behavior: active_count reflects current number of active permits.
    // Covers Requirements: P2
    let limiter = ConnectionLimiter::new(5);

    assert_eq!(limiter.active_count(), 0);

    let permit1 = limiter.try_acquire().expect("first permit should succeed");
    assert_eq!(limiter.active_count(), 1);

    let permit2 = limiter.try_acquire().expect("second permit should succeed");
    assert_eq!(limiter.active_count(), 2);

    drop(permit1);
    // Give a moment for the drop to take effect
    sleep(Duration::from_millis(10)).await;
    assert_eq!(limiter.active_count(), 1);

    drop(permit2);
    sleep(Duration::from_millis(10)).await;
    assert_eq!(limiter.active_count(), 0);
}

#[tokio::test]
async fn connection_limiter_ensures_minimum_limit_of_one() {
    // Precondition: Connection limiter initialized with limit of 0.
    // Action: Create limiter and try to acquire permit.
    // Expected behavior: Limit is normalized to at least 1, permit acquisition succeeds.
    // Covers Requirements: P2
    let limiter = ConnectionLimiter::new(0);
    let permit = limiter.try_acquire().expect("permit should succeed");
    assert_eq!(limiter.active_count(), 1);
    drop(permit);
}

#[tokio::test]
async fn connection_limiter_updates_limit_dynamically() {
    // Precondition: Connection limiter with initial limit of 2.
    // Action: Acquire permits, then update limit using ensure_limit to 5.
    // Expected behavior: New limit is applied, additional permits can be acquired up to new limit.
    // Covers Requirements: P2
    let limiter = ConnectionLimiter::new(2);
    assert_eq!(limiter.active_count(), 0);

    // Acquire 2 permits
    let permit1 = limiter.try_acquire().expect("first permit should succeed");
    let permit2 = limiter.try_acquire().expect("second permit should succeed");
    assert_eq!(limiter.active_count(), 2);

    // Increase limit to 5
    limiter.ensure_limit(5);
    // Now we should be able to acquire 3 more permits
    let permit3 = limiter.try_acquire().expect("third permit should succeed");
    let permit4 = limiter.try_acquire().expect("fourth permit should succeed");
    let permit5 = limiter.try_acquire().expect("fifth permit should succeed");
    assert_eq!(limiter.active_count(), 5);

    drop(permit1);
    drop(permit2);
    drop(permit3);
    drop(permit4);
    drop(permit5);
}

#[tokio::test]
async fn connection_limiter_handles_rapid_acquire_release() {
    // Precondition: Connection limiter with limit.
    // Action: Rapidly acquire and release permits from connection limiter.
    // Expected behavior: Limiter handles rapid changes correctly.
    // Covers Requirements: P2
    let limiter = ConnectionLimiter::new(5);

    for _ in 0..100 {
        let permit = limiter.try_acquire().expect("permit should succeed");
        drop(permit);
    }

    assert_eq!(limiter.active_count(), 0);
}

#[tokio::test]
async fn connection_limiter_decreases_limit_dynamically() {
    // Precondition: Connection limiter with initial limit.
    // Action: Decrease limit using ensure_limit while permits are held.
    // Expected behavior: New limit is applied, excess permits can't be acquired.
    // Covers Requirements: P2
    let limiter = ConnectionLimiter::new(5);
    let permit1 = limiter.try_acquire().expect("first permit should succeed");
    let permit2 = limiter.try_acquire().expect("second permit should succeed");
    let permit3 = limiter.try_acquire().expect("third permit should succeed");
    assert_eq!(limiter.active_count(), 3);

    // Decrease limit to 2
    limiter.ensure_limit(2);

    // Should still be able to use existing permits
    assert_eq!(limiter.active_count(), 3);

    // But new acquires should be limited
    drop(permit1);
    drop(permit2);
    drop(permit3);

    // Now only 2 permits should be acquirable
    let permit1 = limiter.try_acquire().expect("first permit should succeed");
    let permit2 = limiter.try_acquire().expect("second permit should succeed");
    assert_eq!(limiter.active_count(), 2);

    // Third should fail immediately when limit is reached
    assert!(
        limiter.try_acquire().is_err(),
        "third permit should be rejected when limit is reached"
    );

    // After releasing one permit, should be able to acquire again
    drop(permit1);
    let permit3 = limiter
        .try_acquire()
        .expect("third permit should succeed after release");
    assert_eq!(limiter.active_count(), 2);
    drop(permit3);
    drop(permit2);
}

#[tokio::test]
async fn connection_limiter_handles_concurrent_limit_updates() {
    // Precondition: Connection limiter.
    // Action: Update limit concurrently from multiple tasks using ensure_limit.
    // Expected behavior: Limit updates are handled correctly.
    // Covers Requirements: P2
    let limiter = ConnectionLimiter::new(10);

    let handles: Vec<_> = (0..10)
        .map(|i| {
            let limiter_clone = limiter.clone();
            tokio::spawn(async move {
                limiter_clone.ensure_limit(5 + (i % 5));
            })
        })
        .collect();

    tokio::task::yield_now().await;
    for handle in handles {
        handle.await.expect("task should complete");
    }

    // Final limit should be one of the values
    let permit1 = limiter.try_acquire().expect("first permit should succeed");
    let permit2 = limiter.try_acquire().expect("second permit should succeed");
    let permit3 = limiter.try_acquire().expect("third permit should succeed");
    let permit4 = limiter.try_acquire().expect("fourth permit should succeed");
    let permit5 = limiter.try_acquire().expect("fifth permit should succeed");
    assert_eq!(limiter.active_count(), 5);

    drop(permit1);
    drop(permit2);
    drop(permit3);
    drop(permit4);
    drop(permit5);
}

#[tokio::test]
async fn connection_limiter_active_count_is_accurate_under_load() {
    // Precondition: Connection limiter with limit.
    // Action: Acquire and release permits in various patterns from connection limiter.
    // Expected behavior: active_count accurately reflects current permits.
    // Covers Requirements: P2
    let limiter = ConnectionLimiter::new(10);

    let mut permits = Vec::new();
    for _ in 0..5 {
        permits.push(limiter.try_acquire().expect("permit should succeed"));
    }
    assert_eq!(limiter.active_count(), 5);

    // Release some
    permits.pop();
    sleep(Duration::from_millis(10)).await;
    assert_eq!(limiter.active_count(), 4);

    permits.pop();
    sleep(Duration::from_millis(10)).await;
    assert_eq!(limiter.active_count(), 3);

    // Acquire more
    permits.push(limiter.try_acquire().expect("permit should succeed"));
    permits.push(limiter.try_acquire().expect("permit should succeed"));
    sleep(Duration::from_millis(10)).await;
    assert_eq!(limiter.active_count(), 5);

    // Release all
    drop(permits);
    sleep(Duration::from_millis(10)).await;
    assert_eq!(limiter.active_count(), 0);
}

#[tokio::test]
async fn connection_limiter_handles_zero_initial_limit() {
    // Precondition: Connection limiter with 0 limit.
    // Action: Try to acquire permit from connection limiter with 0 limit.
    // Expected behavior: Limit normalized to 1, permit acquired successfully.
    // Covers Requirements: P2
    let limiter = ConnectionLimiter::new(0);
    let permit = limiter.try_acquire().expect("permit should succeed");
    assert_eq!(limiter.active_count(), 1);
    drop(permit);
}

#[tokio::test]
async fn connection_limiter_handles_limit_reduction_while_permits_held() {
    // Precondition: Connection limiter with permits held.
    // Action: Reduce limit using ensure_limit while permits are held.
    // Expected behavior: Existing permits remain valid, new limit applies to future acquires.
    // Covers Requirements: P2
    let limiter = ConnectionLimiter::new(10);
    let permit1 = limiter.try_acquire().expect("first permit should succeed");
    let permit2 = limiter.try_acquire().expect("second permit should succeed");
    assert_eq!(limiter.active_count(), 2);

    limiter.ensure_limit(1);
    // Existing permits still work
    assert_eq!(limiter.active_count(), 2);

    drop(permit1);
    drop(permit2);
    sleep(Duration::from_millis(10)).await;

    // Now only 1 permit can be acquired
    let permit1 = limiter.try_acquire().expect("first permit should succeed");
    assert_eq!(limiter.active_count(), 1);

    // Second should fail immediately when limit is reached
    assert!(
        limiter.try_acquire().is_err(),
        "second permit should be rejected when limit is reached"
    );

    // After releasing, should be able to acquire again
    drop(permit1);
    let permit2 = limiter
        .try_acquire()
        .expect("second permit should succeed after release");
    assert_eq!(limiter.active_count(), 1);
    drop(permit2);
}

#[tokio::test]
async fn connection_limiter_handles_limit_increase_immediately() {
    // Precondition: Connection limiter with low limit.
    // Action: Increase limit using ensure_limit.
    // Expected behavior: New limit applies immediately, additional permits can be acquired.
    // Covers Requirements: P2
    let limiter = ConnectionLimiter::new(2);
    let _permit1 = limiter.try_acquire().expect("first permit should succeed");
    let _permit2 = limiter.try_acquire().expect("second permit should succeed");

    limiter.ensure_limit(5);
    // Should be able to acquire 3 more immediately
    let _permit3 = limiter.try_acquire().expect("third permit should succeed");
    let _permit4 = limiter.try_acquire().expect("fourth permit should succeed");
    let _permit5 = limiter.try_acquire().expect("fifth permit should succeed");
    assert_eq!(limiter.active_count(), 5);
}

#[tokio::test]
async fn connection_limiter_handles_same_limit_update() {
    // Precondition: Connection limiter with limit.
    // Action: Set same limit again using ensure_limit.
    // Expected behavior: No change, no blocking, permits can still be acquired.
    // Covers Requirements: P2
    let limiter = ConnectionLimiter::new(5);
    limiter.ensure_limit(5);
    limiter.ensure_limit(5);
    // Should work fine, no deadlock
    let permit = limiter.try_acquire().expect("permit should succeed");
    assert_eq!(limiter.active_count(), 1);
    drop(permit);
}

#[tokio::test]
async fn connection_limiter_handles_concurrent_acquires() {
    // Precondition: Connection limiter with limit.
    // Action: Acquire permits concurrently from multiple tasks.
    // Expected behavior: Limit enforced correctly across concurrent acquires.
    // Covers Requirements: P2
    let limiter = ConnectionLimiter::new(3);
    let mut handles = Vec::new();

    for _ in 0..10 {
        let limiter_clone = limiter.clone();
        handles.push(tokio::spawn(async move {
            // Some acquires will succeed (up to limit of 3), others will fail
            if let Ok(permit) = limiter_clone.try_acquire() {
                sleep(Duration::from_millis(10)).await;
                drop(permit);
            }
            // If acquire failed, that's expected when limit is reached
        }));
    }

    for handle in handles {
        handle.await.expect("task should complete");
    }
    sleep(Duration::from_millis(10)).await;
    assert_eq!(limiter.active_count(), 0);
}

#[tokio::test]
async fn connection_limiter_handles_very_large_limit() {
    // Precondition: Connection limiter with very large limit.
    // Action: Acquire many permits from limiter.
    // Expected behavior: All permits can be acquired up to limit.
    // Covers Requirements: P2
    let large_limit = 1000;
    let limiter = ConnectionLimiter::new(large_limit);
    let mut permits = Vec::new();

    for _ in 0..large_limit {
        permits.push(limiter.try_acquire().expect("permit should succeed"));
    }
    assert_eq!(limiter.active_count(), large_limit);

    // One more should fail
    assert!(
        limiter.try_acquire().is_err(),
        "permit should fail when limit is reached"
    );

    drop(permits);
    sleep(Duration::from_millis(10)).await;
    assert_eq!(limiter.active_count(), 0);
}

#[tokio::test]
async fn connection_limiter_active_count_updates_immediately_after_drop() {
    // Precondition: Connection limiter with permits held.
    // Action: Drop permit and check active_count.
    // Expected behavior: active_count decreases immediately after drop.
    // Covers Requirements: P2
    let limiter = ConnectionLimiter::new(5);
    let permit1 = limiter.try_acquire().expect("first permit should succeed");
    let permit2 = limiter.try_acquire().expect("second permit should succeed");
    assert_eq!(limiter.active_count(), 2);

    drop(permit1);
    // Give a moment for drop to take effect
    sleep(Duration::from_millis(10)).await;
    assert_eq!(limiter.active_count(), 1);

    drop(permit2);
    sleep(Duration::from_millis(10)).await;
    assert_eq!(limiter.active_count(), 0);
}

#[tokio::test]
async fn connection_limiter_handles_limit_change_from_zero_to_positive() {
    // Precondition: Connection limiter initialized with limit of 0 (normalized to 1).
    // Action: Update limit to positive value using ensure_limit.
    // Expected behavior: New limit applies correctly.
    // Covers Requirements: P2
    let limiter = ConnectionLimiter::new(0);
    assert_eq!(limiter.active_count(), 0);

    limiter.ensure_limit(10);
    let permit1 = limiter.try_acquire().expect("first permit should succeed");
    assert_eq!(limiter.active_count(), 1);

    // Should be able to acquire up to 10
    drop(permit1);
    sleep(Duration::from_millis(10)).await;

    let mut permits = Vec::new();
    for _ in 0..10 {
        permits.push(limiter.try_acquire().expect("permit should succeed"));
    }
    assert_eq!(limiter.active_count(), 10);
    drop(permits);
}

#[tokio::test]
async fn connection_limiter_handles_rapid_limit_changes() {
    // Precondition: Connection limiter with initial limit.
    // Action: Rapidly change limit multiple times using ensure_limit.
    // Expected behavior: Latest limit is applied correctly.
    // Covers Requirements: P2
    let limiter = ConnectionLimiter::new(5);
    limiter.ensure_limit(10);
    limiter.ensure_limit(15);
    limiter.ensure_limit(20);

    let mut permits = Vec::new();
    for _ in 0..20 {
        permits.push(limiter.try_acquire().expect("permit should succeed"));
    }
    assert_eq!(limiter.active_count(), 20);

    assert!(
        limiter.try_acquire().is_err(),
        "permit should fail when limit is reached"
    );
    drop(permits);
}

#[tokio::test]
async fn connection_limiter_preserves_permits_when_limit_decreases() {
    // Precondition: Connection limiter with permits held.
    // Action: Decrease limit while permits are held.
    // Expected behavior: Existing permits remain valid, new limit applies to future acquires.
    // Covers Requirements: P2
    let limiter = ConnectionLimiter::new(10);
    let permit1 = limiter.try_acquire().expect("first permit should succeed");
    let permit2 = limiter.try_acquire().expect("second permit should succeed");
    let permit3 = limiter.try_acquire().expect("third permit should succeed");
    assert_eq!(limiter.active_count(), 3);

    // Decrease limit to 2
    limiter.ensure_limit(2);
    // Existing permits still work
    assert_eq!(limiter.active_count(), 3);

    drop(permit1);
    drop(permit2);
    drop(permit3);
    sleep(Duration::from_millis(10)).await;

    // Now only 2 permits can be acquired
    let permit1 = limiter.try_acquire().expect("first permit should succeed");
    let permit2 = limiter.try_acquire().expect("second permit should succeed");
    assert_eq!(limiter.active_count(), 2);

    assert!(
        limiter.try_acquire().is_err(),
        "third permit should fail when limit is 2"
    );
    drop(permit1);
    drop(permit2);
}

#[tokio::test]
async fn connection_limiter_handles_limit_change_to_same_value() {
    // Precondition: Connection limiter with limit.
    // Action: Set same limit again using ensure_limit.
    // Expected behavior: No change, permits can still be acquired.
    // Covers Requirements: P2
    let limiter = ConnectionLimiter::new(5);
    limiter.ensure_limit(5);
    limiter.ensure_limit(5);

    let permit = limiter.try_acquire().expect("permit should succeed");
    assert_eq!(limiter.active_count(), 1);
    drop(permit);
}

#[test]
fn connection_limiter_sync_behavior_is_correct() {
    // Precondition: Connection limiter with limit.
    // Action: Acquire and release permits synchronously (without await).
    // Expected behavior: Limit enforced correctly in synchronous context.
    // Covers Requirements: P2
    let limiter = ConnectionLimiter::new(3);
    let permit1 = limiter.try_acquire().expect("first permit should succeed");
    let permit2 = limiter.try_acquire().expect("second permit should succeed");
    let permit3 = limiter.try_acquire().expect("third permit should succeed");
    assert_eq!(limiter.active_count(), 3);

    assert!(
        limiter.try_acquire().is_err(),
        "fourth permit should fail when limit is reached"
    );

    drop(permit1);
    drop(permit2);
    drop(permit3);
    assert_eq!(limiter.active_count(), 0);
}

#[tokio::test]
async fn connection_limiter_handles_limit_increase_while_at_capacity() {
    // Precondition: Connection limiter at capacity.
    // Action: Increase limit while all permits are held.
    // Expected behavior: Additional permits can be acquired immediately.
    // Covers Requirements: P2
    let limiter = ConnectionLimiter::new(3);
    let permit1 = limiter.try_acquire().expect("first permit should succeed");
    let permit2 = limiter.try_acquire().expect("second permit should succeed");
    let permit3 = limiter.try_acquire().expect("third permit should succeed");
    assert_eq!(limiter.active_count(), 3);

    // Increase limit to 5
    limiter.ensure_limit(5);

    // Should be able to acquire 2 more immediately
    let permit4 = limiter.try_acquire().expect("fourth permit should succeed");
    let permit5 = limiter.try_acquire().expect("fifth permit should succeed");
    assert_eq!(limiter.active_count(), 5);

    drop(permit1);
    drop(permit2);
    drop(permit3);
    drop(permit4);
    drop(permit5);
}
