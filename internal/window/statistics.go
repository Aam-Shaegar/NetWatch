package window

import "math"

// moments maintains population variance without retaining individual samples.
type moments struct {
	n        uint64
	mean, m2 float64
}

func (m *moments) add(x float64) {
	m.n++
	delta := x - m.mean
	m.mean += delta / float64(m.n)
	m.m2 += delta * (x - m.mean)
}

func (m moments) values() (mean, std *float64) {
	if m.n == 0 {
		return nil, nil
	}
	average := m.mean
	deviation := math.Sqrt(math.Max(0, m.m2/float64(m.n)))
	return &average, &deviation
}

func fraction(n, total uint64) *float64 {
	if total == 0 {
		return nil
	}
	v := float64(n) / float64(total)
	return &v
}
