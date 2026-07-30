package risk

import "github.com/princebabou/Latch/pkg/models"

// signalCollector keeps detector output stable and prevents one behavior from
// inflating the aggregate score merely because it appeared multiple times.
// When analyzers report the same behavior, the strongest finding wins.
type signalCollector struct {
	order []string
	byID  map[string]models.RiskSignal
}

func newSignalCollector() *signalCollector {
	return &signalCollector{byID: make(map[string]models.RiskSignal)}
}

func (collector *signalCollector) add(name string, score int, description string) {
	existing, found := collector.byID[name]
	if !found {
		collector.order = append(collector.order, name)
		collector.byID[name] = models.RiskSignal{Name: name, Score: score, Description: description}
		return
	}
	if score > existing.Score {
		collector.byID[name] = models.RiskSignal{Name: name, Score: score, Description: description}
	}
}

func (collector *signalCollector) signals() []models.RiskSignal {
	signals := make([]models.RiskSignal, 0, len(collector.order))
	for _, name := range collector.order {
		signals = append(signals, collector.byID[name])
	}
	return signals
}
