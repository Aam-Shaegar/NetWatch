CREATE INDEX feature_windows_recent_receipt ON feature_windows(received_at DESC, event_id DESC);
CREATE INDEX predictions_target_recent ON predictions(model_id, policy_version, processed_at DESC, event_id DESC);
CREATE INDEX predictions_target_recent_usable ON predictions(model_id, policy_version, processed_at DESC, event_id DESC)
 WHERE payload->>'status' IN ('normal','anomalous');
