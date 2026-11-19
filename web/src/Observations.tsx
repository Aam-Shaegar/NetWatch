import { useEffect, useState } from "react";

type Finding = {
  label: string;
  basis: string;
  kind?:
    | "traffic_pattern"
    | "degradation_pattern"
    | "security_indicator"
    | "waf_signal";
};

const availabilityLabels = {
  reachable: "Пробы прошли",
  degraded: "Есть отказы проб",
  unmeasured: "Доступность не измерена",
};

function findingText(finding: Finding) {
  const { kind, basis, label } = finding;
  if (kind === "waf_signal" || basis === "upstream_waf")
    return "Сигнал WAF · " + label;
  if (basis === "burst_with_silent_reference")
    return "Всплеск после тишины · " + label;
  if (kind === "traffic_pattern") return "Отклонение нагрузки · " + label;
  if (kind === "degradation_pattern") return "Перегрузка с отказами · " + label;
  if (kind === "security_indicator") return "Признаки атаки · " + label;
  return label;
}

type Observation = {
  id: string;
  sensor: string;
  observation: { entity: string; start_s: number };
  assessment: {
    ruleset: string;
    evaluated: number;
    availability?: keyof typeof availabilityLabels;
    scheduled_change?: boolean;
    findings: Finding[];
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
            {row.assessment.findings.map(findingText).join(", ") ||
              (row.assessment.evaluated
                ? "В проверенных правилах нет совпадений"
                : "Недостаточно данных")}
          </summary>
          <p>
            Сенсор {row.sensor} · Правила {row.assessment.ruleset}
          </p>
          {row.assessment.availability && (
            <p>{availabilityLabels[row.assessment.availability]}</p>
          )}
          {row.assessment.scheduled_change && <p>Запланированное изменение</p>}
          {Object.keys(row.assessment.unassessed).length > 0 && (
            <p>
              Правил без достаточных данных{" "}
              {Object.keys(row.assessment.unassessed).length}
            </p>
          )}
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
