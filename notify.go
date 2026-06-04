package main

// onCapture, when set (by the GUI), is invoked after each successful capture so
// the front-end can show a notification. Nil in console/service mode.
var onCapture func(j *job)

// notifyCapture fires the capture hook if enabled and set.
func notifyCapture(j *job) {
	if cfg.Notifications && onCapture != nil {
		onCapture(j)
	}
}

// firstNonEmpty returns the first non-empty string of its arguments, or "".
func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
