package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"
)

const mainMenu = `NETWATCH

1. Статистика аномалий
2. Сенсоры
3. Тестирование
0. Выход
> `

const sensorMenu = `
СЕНСОРЫ

1. Список сенсоров
2. Добавить сенсор и получить одноразовый код
3. Выбрать сенсор
0. Назад
> `

const testMenu = `
ТЕСТИРОВАНИЕ

1. Обнаружение аномалий
2. Классификация атак
3. Полный конвейер
4. Сравнение моделей
0. Назад
> `

type terminal struct {
	in  *bufio.Scanner
	out io.Writer
	err io.Writer
}

func runMenu(ctx context.Context, o options, in io.Reader, out, errOut io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 512), 4096)
	t := terminal{scanner, out, errOut}
	var client *operatorClient
	defer func() {
		if client != nil {
			client.http.CloseIdleConnections()
		}
	}()
	for {
		choice, err := t.ask(mainMenu)
		if errors.Is(err, io.EOF) || (err == nil && choice == "0") {
			return nil
		}
		if err != nil {
			return err
		}
		switch choice {
		case "1", "2":
			if client == nil {
				client, err = newClient(o)
				if err != nil {
					t.report(err)
					continue
				}
			}
			if choice == "1" {
				err = client.printCatalog(ctx, out)
			} else {
				err = t.sensors(ctx, client)
			}
		case "3":
			err = t.tests(ctx)
		default:
			fmt.Fprintln(out, "Выберите пункт меню.")
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		t.report(err)
	}
}

func (t terminal) ask(prompt string) (string, error) {
	if _, err := io.WriteString(t.out, prompt); err != nil {
		return "", err
	}
	if t.in.Scan() {
		return strings.TrimSpace(t.in.Text()), nil
	}
	if err := t.in.Err(); err != nil {
		return "", err
	}
	return "", io.EOF
}

func (t terminal) report(err error) {
	if err != nil {
		fmt.Fprintln(t.err, "netwatch:", err)
	}
}

func (c *operatorClient) printCatalog(ctx context.Context, out io.Writer) error {
	var summary struct {
		Total    int64            `json:"total"`
		ByType   map[string]int64 `json:"by_type"`
		BySource map[string]int64 `json:"by_source"`
		Recent   []struct {
			Type     string `json:"type"`
			Source   string `json:"source"`
			Sensor   string `json:"sensor_id"`
			Entity   string `json:"entity_id"`
			First    string `json:"first_ns"`
			Last     string `json:"last_ns"`
			Detector string `json:"detector_version"`
		} `json:"incidents"`
	}
	if err := c.get(ctx, "/v1/catalog/incidents", nil, &summary); err != nil {
		return err
	}
	var types []string
	for typ := range summary.ByType {
		if typ != "unknown" {
			types = append(types, typ)
		}
	}
	slices.Sort(types)
	var text strings.Builder
	fmt.Fprintf(&text, "\nВсего инцидентов: %d\nПравила: %d\nML: %d\nНеизвестных: %d\n",
		summary.Total, summary.BySource["rules"], summary.BySource["ml"], summary.ByType["unknown"])
	for _, typ := range types {
		fmt.Fprintf(&text, "%q: %d\n", typ, summary.ByType[typ])
	}
	if len(summary.Recent) > 0 {
		fmt.Fprintln(&text, "\nПоследние инциденты")
		for _, item := range summary.Recent {
			fmt.Fprintf(&text, "%s — %s %q %q, сенсор %q, узел %q, версия %q\n",
				eventTime(item.First), eventTime(item.Last), item.Type, item.Source, item.Sensor, item.Entity, item.Detector)
		}
	}
	_, err := io.WriteString(out, text.String())
	return err
}

var (
	sensorIDPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	enrollmentCodePattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

func (t terminal) sensors(ctx context.Context, client *operatorClient) error {
	for {
		choice, err := t.ask(sensorMenu)
		if err != nil || choice == "0" {
			return err
		}
		switch choice {
		case "1":
			var result struct {
				Sensors []struct {
					ID       string     `json:"id"`
					State    string     `json:"state"`
					LastSeen *time.Time `json:"last_seen_at"`
				} `json:"sensors"`
			}
			err = client.get(ctx, "/v1/sensors", nil, &result)
			if err == nil {
				if len(result.Sensors) == 0 {
					fmt.Fprintln(t.out, "Нет зарегистрированных сенсоров.")
				}
				for _, sensor := range result.Sensors {
					lastSeen := "нет связи"
					if sensor.LastSeen != nil {
						lastSeen = sensor.LastSeen.UTC().Format(time.RFC3339)
					}
					fmt.Fprintf(t.out, "%q: %q, последняя связь %s\n", sensor.ID, sensor.State, lastSeen)
				}
			}
		case "2", "3":
			id, readErr := t.ask("Идентификатор сенсора (Enter для возврата): ")
			if readErr != nil {
				return readErr
			}
			if id == "" {
				continue
			}
			if !sensorIDPattern.MatchString(id) {
				t.report(errors.New("идентификатор должен содержать от 1 до 64 букв ASCII, цифр или символов . _ - и начинаться с буквы или цифры"))
				continue
			}
			if choice == "2" {
				err = t.enrollSensor(ctx, client, id)
			} else {
				err = t.changeSensor(ctx, client, id)
			}
		default:
			fmt.Fprintln(t.out, "Выберите пункт меню.")
		}
		if errors.Is(err, io.EOF) {
			return err
		}
		t.report(err)
	}
}

func (t terminal) enrollSensor(ctx context.Context, client *operatorClient, id string) error {
	var result struct {
		Code      string    `json:"code"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := client.post(ctx, "/v1/sensors/enrollment", map[string]string{"id": id}, &result); err != nil {
		return err
	}
	if !enrollmentCodePattern.MatchString(result.Code) || result.ExpiresAt.IsZero() {
		return errors.New("сервер не вернул действительный код регистрации")
	}
	_, err := fmt.Fprintf(t.out, "Одноразовый код для %q\n%s\nДействует до %s. Введите его в приглашении сенсора.\n",
		id, result.Code, result.ExpiresAt.UTC().Format(time.RFC3339))
	return err
}

func (t terminal) changeSensor(ctx context.Context, client *operatorClient, id string) error {
	prompt := fmt.Sprintf("\nСенсор %q\n1. Приостановить\n2. Возобновить\n3. Отозвать доступ\n0. Назад\n> ", id)
	choice, err := t.ask(prompt)
	if err != nil || choice == "0" {
		return err
	}
	action := map[string]string{"1": "pause", "2": "resume", "3": "revoke"}[choice]
	if action == "" {
		return errors.New("выберите пункт меню")
	}
	if action == "revoke" {
		confirm, err := t.ask("Подтвердите отзыв доступа (1 — отозвать, 0 — отменить): ")
		if err != nil || confirm != "1" {
			return err
		}
	}
	if err := client.post(ctx, "/v1/sensors/"+id+"/"+action, nil, nil); err != nil {
		return err
	}
	_, err = fmt.Fprintln(t.out, "Состояние сенсора обновлено.")
	return err
}

func (t terminal) tests(ctx context.Context) error {
	for {
		choice, err := t.ask(testMenu)
		if err != nil || choice == "0" {
			return err
		}
		target := map[string]string{"1": "test-find", "2": "test-classify", "3": "test-pipeline"}[choice]
		if choice == "4" {
			t.report(t.runTests(ctx, "test-find", "test-classify", "MODEL="))
		} else if target == "" {
			fmt.Fprintln(t.out, "Выберите пункт меню.")
		} else {
			t.report(t.runTests(ctx, target))
		}
	}
}

func (t terminal) runTests(ctx context.Context, targets ...string) error {
	dir := os.Getenv("NETWATCH_PROJECT_DIR")
	if dir == "" {
		dir = "."
	}
	cmd := exec.CommandContext(ctx, "make", targets...)
	cmd.Dir, cmd.Stdout, cmd.Stderr = dir, t.out, t.err
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("проверка %s в %q: %w", strings.Join(targets, ", "), dir, err)
	}
	return nil
}
