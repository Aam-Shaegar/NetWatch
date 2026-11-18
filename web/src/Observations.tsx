import { useEffect, useState } from "react";

type Observation = {
  id: string;
  sensor: string;
  observation: { entity: string; start_s: number };
  assessment: {
    ruleset: string;
    evaluated: number;
    findings: { label: string }[];
    unassessed: Record<string, string[]>;
  };
};

export function Observations({
  token,
  entity,
  revision,
}: {
  token: string;
  entity: string;
  revision: number;
}) {
  const [cursor, page] = useState("");
  const [rows, setRows] = useState<Observation[]>([]);
  const [next, setNext] = useState("");
  const [error, setError] = useState("");
  useEffect(() => {
    const ac = new AbortController();
    setRows([]);
    setNext("");
    setError("");
    const query = new URLSearchParams({ entity, before: cursor });
    fetch("/v1/security/observations?" + query, {
      signal: ac.signal,
      headers: { Authorization: "Bearer " + token },
    })
      .then(async (r) => {
        if (!r.ok) throw Error("Не удалось загрузить наблюдения.");
        return r.json();
      })
      .then((data) => {
        if (!ac.signal.aborted) {
          setRows(data.observations);
          setNext(data.next);
        }
      })
      .catch((e) => {
        if (!ac.signal.aborted) setError(e.message);
      });
    return () => ac.abort();
  }, [cursor, token, entity, revision]);
  return (
    <section aria-label="Минутные наблюдения">
      <h2>Минутные наблюдения</h2>
      {error && <p role="alert">{error}</p>}
      {rows.map((row) => (
        <details key={row.id}>
          <summary>
            {new Date(row.observation.start_s * 1000).toLocaleString("ru-RU", {
              timeZone: "UTC",
            }) + " UTC"}{" "}
            · {row.observation.entity} ·{" "}
            {row.assessment.findings.map((f) => f.label).join(", ") ||
              (row.assessment.evaluated
                ? "Нет совпадений"
                : "Недостаточно данных")}
          </summary>
          <p>
            Сенсор {row.sensor} · Правила {row.assessment.ruleset}
          </p>
          <pre>
            {JSON.stringify(
              { observation: row.observation, assessment: row.assessment },
              null,
              2,
            )}
          </pre>
        </details>
      ))}
      {next && <button onClick={() => page(next)}>Следующие наблюдения</button>}
      {cursor && <button onClick={() => page("")}>Первые наблюдения</button>}
    </section>
  );
}
