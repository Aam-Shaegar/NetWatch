package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"
)

const pilotUsage = `netwatch pilot start ИМЯ [--json]
netwatch pilot report ИМЯ [--json]
netwatch pilot label ИМЯ --sensor СЕНСОР --id СОБЫТИЕ --from RFC3339 --until RFC3339 --type ТИП [--json]
Имена пилота и события: 1–64 символа (латиница, цифры, дефис или подчёркивание), первый символ — буква или цифра.
Типы разметки: normal, tcp_port_scan, udp_flood, icmp_flood, unknown.`

var pilotNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

type pilotReport struct {
	Name     string        `json:"name"`
	Start    time.Time     `json:"started_at"`
	End      time.Time     `json:"ends_at"`
	AsOf     time.Time     `json:"as_of"`
	Model    string        `json:"model_id"`
	Policy   string        `json:"policy_version"`
	Done     bool          `json:"complete"`
	Sensors  []pilotSensor `json:"sensors"`
	Analyzer struct {
		Samples   int64  `json:"samples"`
		PeakQueue *int64 `json:"peak_queue"`
		Growth    *int64 `json:"database_growth_bytes"`
	} `json:"analyzer"`
}

type pilotSensor struct {
	ID           string           `json:"sensor_id"`
	Expected     int64            `json:"expected_slots"`
	Received     int64            `json:"received_slots"`
	Usable       int64            `json:"usable_slots"`
	Coverage     *float64         `json:"coverage_pct"`
	Windows      int64            `json:"received_windows"`
	Insufficient int64            `json:"insufficient_windows"`
	Unresolved   int64            `json:"unresolved_windows"`
	AlertWindows int64            `json:"alert_windows"`
	Incidents    int64            `json:"incidents"`
	ByType       map[string]int64 `json:"by_type"`
	BySource     map[string]int64 `json:"by_source"`
	Delay        *float64         `json:"p95_delay_s"`
	Samples      int64            `json:"resource_samples"`
	CPU          *float64         `json:"mean_cpu_pct"`
	PeakRSS      *int64           `json:"peak_rss_bytes"`
	Reference    *pilotReference  `json:"reference"`
}

type pilotReference struct {
	Attacks        int64    `json:"attack_episodes"`
	Detected       int64    `json:"detected_episodes"`
	Correct        int64    `json:"correctly_typed_episodes"`
	NormalSlots    int64    `json:"normal_slots"`
	FalseIncidents int64    `json:"false_incidents"`
	FalsePer100h   *float64 `json:"false_per_100h"`
	ByType         map[string]struct {
		Total    int64 `json:"total"`
		Detected int64 `json:"detected"`
		Correct  int64 `json:"correct"`
	} `json:"by_type"`
}

type pilotLabel struct {
	ID     string    `json:"id"`
	Sensor string    `json:"sensor_id"`
	From   time.Time `json:"start"`
	Until  time.Time `json:"end"`
	Type   string    `json:"type"`
}

func runPilot(ctx context.Context, args []string, out, stderr io.Writer) (int, error) {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(out, pilotUsage)
		return 0, nil
	}
	if len(args) < 2 || !slices.Contains([]string{"start", "report", "label"}, args[0]) || !pilotNamePattern.MatchString(args[1]) {
		return 1, errors.New(pilotUsage)
	}
	action, name := args[0], args[1]
	o := options{}
	fs := operatorFlags("pilot "+action, stderr, &o)
	var label pilotLabel
	var from, until string
	if action == "label" {
		fs.StringVar(&label.Sensor, "sensor", "", "идентификатор сенсора")
		fs.StringVar(&label.ID, "id", "", "идентификатор события из независимого журнала")
		fs.StringVar(&from, "from", "", "начало интервала, RFC3339")
		fs.StringVar(&until, "until", "", "конец интервала, RFC3339")
		fs.StringVar(&label.Type, "type", "", "normal, tcp_port_scan, udp_flood, icmp_flood или unknown")
	}
	if err := fs.Parse(args[2:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, nil
		}
		return 1, nil
	}
	if fs.NArg() != 0 {
		return 1, errors.New(pilotUsage)
	}
	if action == "label" {
		var err error
		label.From, err = time.Parse(time.RFC3339Nano, from)
		if err != nil {
			return 1, fmt.Errorf("--from: %w", err)
		}
		label.Until, err = time.Parse(time.RFC3339Nano, until)
		if err != nil {
			return 1, fmt.Errorf("--until: %w", err)
		}
		if !label.Until.After(label.From) || !pilotNamePattern.MatchString(label.ID) || !sensorIDPattern.MatchString(label.Sensor) ||
			!slices.Contains([]string{"normal", "tcp_port_scan", "udp_flood", "icmp_flood", "unknown"}, label.Type) {
			return 1, errors.New("проверьте --sensor, --id, --type и порядок границ интервала разметки")
		}
		label.From, label.Until = label.From.UTC(), label.Until.UTC()
	}
	client, err := newClient(o)
	if err != nil {
		return 1, err
	}
	defer client.http.CloseIdleConnections()
	if action == "label" {
		var result json.RawMessage
		err := client.post(ctx, "/v1/pilots/"+name+"/labels", label, &result)
		if err != nil {
			return 1, err
		}
		if o.machine {
			return 0, json.NewEncoder(out).Encode(result)
		}
		_, err = fmt.Fprintf(out, "Разметка %s для сенсора %s сохранена в пилоте %s.\n", label.ID, label.Sensor, name)
		return 0, err
	}
	if action == "report" {
		client.http.Timeout = 120 * time.Second
	}
	return 0, client.pilot(ctx, action, name, o.machine, out)
}

func (c *operatorClient) pilot(ctx context.Context, action, name string, machine bool, out io.Writer) error {
	path := "/v1/pilots/" + name + "/" + action
	var raw json.RawMessage
	var err error
	if action == "start" {
		err = c.post(ctx, path, nil, &raw)
	} else {
		err = c.get(ctx, path, nil, &raw)
	}
	if err != nil {
		return err
	}
	var report pilotReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return err
	}
	if report.Name != name || report.Start.IsZero() || !report.End.After(report.Start) ||
		(action == "report" && (report.AsOf.IsZero() || report.Sensors == nil)) {
		return fmt.Errorf("неполный ответ анализатора о пилоте %q", name)
	}
	if machine {
		return json.NewEncoder(out).Encode(raw)
	}
	return report.print(out, action == "start")
}

func pilotMetric(value *float64, format string) string {
	if value == nil {
		return "нет данных"
	}
	return fmt.Sprintf(format, *value)
}

func pilotCounts(counts map[string]int64) string {
	items := make([]string, 0, len(counts))
	for _, label := range slices.Sorted(maps.Keys(counts)) {
		items = append(items, fmt.Sprintf("%s=%d", label, counts[label]))
	}
	return strings.Join(items, ", ")
}

func (r pilotReport) print(out io.Writer, start bool) error {
	var text strings.Builder
	fmt.Fprintf(&text, "Пилот %s\nПериод (UTC): %s — %s\nМодель: %s, политика: %s\n",
		r.Name, r.Start.UTC().Format(time.RFC3339), r.End.UTC().Format(time.RFC3339), r.Model, r.Policy)
	if start {
		fmt.Fprintf(&text, "Посмотреть отчёт: netwatch pilot report %s\n", r.Name)
	} else {
		state := "идёт наблюдение"
		if r.Done {
			state = "период завершён"
		}
		fmt.Fprintf(&text, "Отчёт по состоянию на %s (%s)\n", r.AsOf.UTC().Format(time.RFC3339), state)
		fmt.Fprintf(&text, "Анализатор: замеров %d", r.Analyzer.Samples)
		if r.Analyzer.PeakQueue != nil {
			fmt.Fprintf(&text, ", максимум очереди %d", *r.Analyzer.PeakQueue)
		}
		if r.Analyzer.Growth != nil {
			fmt.Fprintf(&text, ", изменение объёма БД %+.2f МиБ", float64(*r.Analyzer.Growth)/(1024*1024))
		}
		text.WriteByte('\n')
		if len(r.Sensors) == 0 {
			text.WriteString("За период не зарегистрирован ни один сенсор.\n")
		}
		for _, s := range r.Sensors {
			fmt.Fprintf(&text, "\nСенсор %s\n", s.ID)
			fmt.Fprintf(&text, "  Интервалы по 5 с: запланировано %d, получено %d, пригодно %d. Покрытие: %s\n",
				s.Expected, s.Received, s.Usable, pilotMetric(s.Coverage, "%.2f%%"))
			fmt.Fprintf(&text, "  Окна: всего %d, недостаточно данных %d, без решения %d, с тревогой %d\n",
				s.Windows, s.Insufficient, s.Unresolved, s.AlertWindows)
			fmt.Fprintf(&text, "  Задержка до решения (p95): %s\n", pilotMetric(s.Delay, "%.3f с"))
			fmt.Fprintf(&text, "  Инциденты: %d\n", s.Incidents)
			if s.Incidents > 0 {
				fmt.Fprintf(&text, "  По типу: %s. По источнику: %s\n", pilotCounts(s.ByType), pilotCounts(s.BySource))
			}
			rss := "нет данных"
			if s.PeakRSS != nil {
				rss = fmt.Sprintf("%.1f МиБ", float64(*s.PeakRSS)/(1024*1024))
			}
			fmt.Fprintf(&text, "  Ресурсы сенсора: замеров %d, средний CPU %s, пиковый RSS %s\n",
				s.Samples, pilotMetric(s.CPU, "%.1f%%"), rss)
			if ref := s.Reference; ref != nil {
				fmt.Fprintf(&text, "  По разметке: обнаружено %d/%d эпизодов, верно определён тип %d/%d\n",
					ref.Detected, ref.Attacks, ref.Correct, ref.Attacks)
				for _, kind := range slices.Sorted(maps.Keys(ref.ByType)) {
					row := ref.ByType[kind]
					fmt.Fprintf(&text, "    %s: обнаружено %d/%d, верно определён тип %d/%d\n",
						kind, row.Detected, row.Total, row.Correct, row.Total)
				}
				fmt.Fprintf(&text, "  Пригодных штатных интервалов по 5 с: %d. Ложных инцидентов: %d. На 100 хост-часов: %s\n",
					ref.NormalSlots, ref.FalseIncidents, pilotMetric(ref.FalsePer100h, "%.2f"))
			} else {
				text.WriteString("  Для оценки обнаружения и ложных тревог нет разметки.\n")
			}
		}
	}
	_, err := io.WriteString(out, text.String())
	return err
}
