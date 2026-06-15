import React from "react";

export function Panel({
  index,
  title,
  right,
  bodyClassName,
  noBody,
  style,
  children,
}: {
  index?: string;
  title?: string;
  right?: React.ReactNode;
  bodyClassName?: string;
  noBody?: boolean;
  style?: React.CSSProperties;
  children: React.ReactNode;
}) {
  return (
    <section className="panel" style={style}>
      {(title || right) && (
        <div className="panel__head">
          <div className="panel__title">
            {index && <span className="panel__index">{index}</span>}
            {title && <h2>{title}</h2>}
          </div>
          {right}
        </div>
      )}
      {noBody ? children : <div className={`panel__body ${bodyClassName ?? ""}`}>{children}</div>}
    </section>
  );
}
