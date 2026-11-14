import { useEffect, useRef, useState, type FormEvent } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

type Incident = {
  id: string;
  sensor: string;
  entity: string;
  epoch: string;
  model: string;
  policy: string;
  first_ns: string;
  detected_ns: string;
  last_ns: string;
  closed_ns: string | null;
  ack_by: string | null;
  ack_at: string | null;
};
type Evidence = {
  event: string;
  kind: string;
  start_ns: string;
  end_ns: string;
  features: { in_packets: number | null; out_packets: number | null };
  prediction: {
    status: string;
    score: number | null;
    threshold: number | null;
  };
};
type Detail = {
  schema_version: number;
  feature_set_version: string;
  rule: string;
  incident: Incident;
  events: Evidence[];
  more: boolean;
};
const when = (ns: string) =>
  new Date(Number(BigInt(ns) / 1000000n)).toLocaleString("ru-RU", {
    timeZone: "UTC",
  });
const fmt = (v: number | null) => (v == null ? "—" : v.toFixed(4));
const kinds: Record<string, string> = {
  opened: "Открытие",
  closed: "Закрытие",
  signal: "Превышение",
  unknown: "Нет оценки",
  observed: "Наблюдение",
};

function EvidenceTable({ events }: { events: Evidence[] }) {
  const total = ({ features }: Evidence) =>
    features.in_packets === null || features.out_packets === null
      ? null
      : features.in_packets + features.out_packets;
  const max = events.reduce((m, event) => Math.max(m, total(event) ?? 0), 1);
  return (
    <table>
      <caption>Трафик по окнам · время UTC</caption>
      <thead>
        <tr>
          <th>Начало</th>
          <th>Пакеты, вход / выход</th>
          <th>Оценка / порог</th>
          <th>Событие</th>
        </tr>
      </thead>
      <tbody>
        {events.map((e) => (
          <tr key={e.event}>
            <td>{when(e.start_ns)}</td>
            <td>
              {e.features.in_packets ?? "—"} / {e.features.out_packets ?? "—"}
              {total(e) !== null && (
                <meter
                  aria-label="Всего пакетов"
                  min="0"
                  max={max}
                  value={total(e)!}
                />
              )}
            </td>
            <td>
              {fmt(e.prediction.score)} / {fmt(e.prediction.threshold)}
            </td>
            <td>{kinds[e.kind]}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function App() {
  const [token, setToken] = useState(""),
    [filter, setFilter] = useState(""),
    [cursor, setCursor] = useState(""),
    [next, setNext] = useState(""),
    [rev, refresh] = useState(0);
  const [items, setItems] = useState<Incident[]>([]),
    [selected, select] = useState(""),
    [card, setCard] = useState<Detail | null>(null);
  const [listError, setListError] = useState(""),
    [cardError, setCardError] = useState(""),
    [busy, setBusy] = useState(false),
    [acting, setActing] = useState(false);
  const [pipeline, setPipeline] = useState({ pending: false, retrying: false });
  const action = useRef<AbortController | null>(null);
  const request = async (path: string, signal: AbortSignal, method = "GET") => {
    const res = await fetch(path, {
      method,
      headers: { Authorization: "Bearer " + token },
      signal,
    });
    if (!res.ok)
      throw Error(
        res.status === 401
          ? "Требуется действующий ключ оператора."
          : "Сервер недоступен или запись не найдена.",
      );
    return res;
  };
  useEffect(() => {
    if (!token) return;
    const ac = new AbortController();
    setBusy(true);
    setListError("");
    setItems([]);
    setNext("");
    const query = new URLSearchParams(filter);
    if (cursor) query.set("before", cursor);
    request("/v1/incidents?" + query, ac.signal)
      .then((r) => r.json())
      .then((d) => {
        if (!ac.signal.aborted) {
          setItems(d.incidents);
          setNext(d.next);
          setPipeline({ pending: d.pending, retrying: d.retrying });
        }
      })
      .catch((e) => {
        if (!ac.signal.aborted) setListError(e.message);
      })
      .finally(() => {
        if (!ac.signal.aborted) setBusy(false);
      });
    return () => ac.abort();
  }, [token, filter, cursor, rev]);
  useEffect(() => {
    const ac = new AbortController();
    setCard(null);
    setCardError("");
    setActing(false);
    if (selected && token)
      request("/v1/incidents/" + selected, ac.signal)
        .then((r) => r.json())
        .then((d) => {
          if (!ac.signal.aborted) setCard(d);
        })
        .catch((e) => {
          if (!ac.signal.aborted) setCardError(e.message);
        });
    return () => {
      ac.abort();
      action.current?.abort();
    };
  }, [token, selected, rev]);
  function apply(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const data = new FormData(e.currentTarget),
      q = new URLSearchParams();
    for (const key of ["entity", "model", "from", "until"]) {
      const v = String(data.get(key) || "");
      if (v)
        q.set(
          key,
          key === "from" || key === "until"
            ? String(BigInt(Date.parse(v + "Z")) * 1000000n)
            : v,
        );
    }
    setFilter(q.toString());
    setCursor("");
    select("");
    refresh((i) => i + 1);
  }
  async function operate(mode: "ack" | "more" | "export") {
    if (!card || acting) return;
    action.current?.abort();
    const ac = new AbortController();
    action.current = ac;
    setActing(true);
    setCardError("");
    try {
      const url = "/v1/incidents/" + card.incident.id;
      if (mode === "ack") {
        await request(url + "/ack", ac.signal, "POST");
        refresh((i) => i + 1);
        return;
      }
      let data = card;
      let events = [...data.events];
      while (data.more) {
        const after = events[events.length - 1].start_ns;
        data = await (await request(url + "?after=" + after, ac.signal)).json();
        events = events.concat(data.events);
        if (mode === "more") break;
      }
      if (ac.signal.aborted) return;
      if (mode === "more") {
        setCard({ ...data, events });
        return;
      }
      const blob = new Blob(
        [
          JSON.stringify(
            { ...data, events, exported_at: new Date().toISOString() },
            null,
            2,
          ),
        ],
        { type: "application/json" },
      );
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = "netwatch-incident-" + card.incident.id + ".json";
      link.click();
      setTimeout(() => URL.revokeObjectURL(link.href), 1000);
    } catch (e) {
      if (!ac.signal.aborted) setCardError(String(e));
    } finally {
      if (!ac.signal.aborted) setActing(false);
    }
  }
  return (
    <main>
      <header>
        <strong>NetWatch</strong>
        <span>Мониторинг сети</span>
      </header>
      <h1>Журнал инцидентов</h1>
      {!token ? (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            setToken(String(new FormData(e.currentTarget).get("token")));
          }}
        >
          <label>
            Ключ оператора
            <input required type="password" name="token" autoComplete="off" />
          </label>
          <button>Открыть журнал</button>
        </form>
      ) : (
        <>
          <form onSubmit={apply}>
            <label>
              Объект
              <input name="entity" />
            </label>
            <label>
              Версия модели
              <input name="model" />
            </label>
            <label>
              С (UTC)
              <input type="datetime-local" name="from" />
            </label>
            <label>
              До (UTC)
              <input type="datetime-local" name="until" />
            </label>
            <button>Применить</button>
          </form>
          <nav>
            <button onClick={() => refresh((i) => i + 1)}>Обновить</button>
            <button
              onClick={() => {
                setToken("");
                select("");
                setCursor("");
                setFilter("");
              }}
            >
              Выйти
            </button>
          </nav>
          {!busy && !listError && pipeline.pending && (
            <p role="status">
              {pipeline.retrying
                ? "Обработка задержана. В очереди есть задания для повторной попытки."
                : "В очереди есть окна, которые ещё не обработаны."}
            </p>
          )}
          <section aria-label="Список инцидентов" aria-busy={busy}>
            {busy ? (
              <p role="status">Загрузка…</p>
            ) : listError ? (
              <p role="alert">{listError}</p>
            ) : items.length === 0 ? (
              <p role="status">Инцидентов по этому запросу нет.</p>
            ) : (
              <ul>
                {items.map((i) => (
                  <li key={i.id}>
                    <button
                      aria-pressed={selected === i.id}
                      onClick={() => select(i.id)}
                    >
                      Инцидент №{i.id} · {i.entity}
                    </button>{" "}
                    <span>
                      {i.closed_ns ? "Закрыт" : "Открыт"} ·{" "}
                      {when(i.detected_ns)} UTC
                    </span>
                  </li>
                ))}
              </ul>
            )}
            {next && (
              <button
                onClick={() => {
                  select("");
                  setCursor(next);
                }}
              >
                Следующая страница
              </button>
            )}
            {cursor && (
              <button
                onClick={() => {
                  select("");
                  setCursor("");
                }}
              >
                К началу
              </button>
            )}
          </section>
          {cardError && <p role="alert">{cardError}</p>}
          {selected && !card && !cardError && (
            <p role="status">Загрузка карточки…</p>
          )}
          {card && (
            <section aria-label="Карточка инцидента">
              <h2>Инцидент №{card.incident.id}</h2>
              <p>
                Два или три превышения порога в трёх последовательных окнах.
              </p>
              <dl>
                {Object.entries({
                  Объект: card.incident.entity,
                  Сенсор: card.incident.sensor,
                  Модель: card.incident.model,
                  Политика: card.incident.policy,
                  "Первый сигнал (UTC)": when(card.incident.first_ns),
                  "Обнаружен (UTC)": when(card.incident.detected_ns),
                  "Закрыт (UTC)": card.incident.closed_ns
                    ? when(card.incident.closed_ns)
                    : "Открыт",
                  Просмотр: card.incident.ack_by || "Ожидает подтверждения",
                }).map(([k, v]) => (
                  <div key={k}>
                    <dt>{k}</dt>
                    <dd>{v}</dd>
                  </div>
                ))}
              </dl>
              <nav>
                {!card.incident.ack_by && (
                  <button disabled={acting} onClick={() => operate("ack")}>
                    Подтвердить просмотр
                  </button>
                )}
                <button disabled={acting} onClick={() => operate("export")}>
                  Скачать JSON
                </button>
              </nav>
              <div className="evidence">
                <EvidenceTable events={card.events} />
              </div>
              {card.more && (
                <button disabled={acting} onClick={() => operate("more")}>
                  Ещё окна
                </button>
              )}
            </section>
          )}
        </>
      )}
    </main>
  );
}
createRoot(document.getElementById("root")!).render(<App />);
