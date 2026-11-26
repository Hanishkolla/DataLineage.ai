"""Milestone 30: SQL Server, Oracle and Airflow metadata export analysis."""
from typing import Any
MAX_OBJECTS=100000
PROVIDERS={"sqlserver","oracle"}
def _txt(v, limit=500): return str(v or "").strip()[:limit]
def normalize_database_snapshot(snapshot: dict[str,Any], provider: str):
    provider=provider.lower()
    if provider not in PROVIDERS: raise ValueError("provider must be sqlserver or oracle")
    if not isinstance(snapshot,dict): raise ValueError("snapshot must be a JSON object")
    raw=snapshot.get("tables",[])
    if not isinstance(raw,list) or len(raw)>MAX_OBJECTS: raise ValueError("tables must be a bounded list")
    tables=[]; seen=set()
    for item in raw:
        if not isinstance(item,dict): continue
        name=_txt(item.get("name") or item.get("table_name"))
        schema=_txt(item.get("schema") or item.get("table_schema") or item.get("owner"))
        if not name: continue
        key=(schema+"."+name).casefold()
        if key in seen: continue
        seen.add(key); cols=item.get("columns",[])
        if not isinstance(cols,list): cols=[]
        columns=[]
        for c in cols:
            if isinstance(c,dict) and (c.get("name") or c.get("column_name")):
                columns.append({"name":_txt(c.get("name") or c.get("column_name")),"type":_txt(c.get("type") or c.get("data_type") or "unknown"),"nullable":c.get("nullable")})
        tables.append({"name":name,"schema":schema,"columns":columns})
    return {"provider":provider,"table_count":len(tables),"tables":tables,"warnings":["Imported metadata snapshot only; live database connectivity and runtime lineage were not evaluated."]}
def compare_database_snapshots(before,after,provider):
    old=normalize_database_snapshot(before,provider); new=normalize_database_snapshot(after,provider)
    key=lambda t:(t["schema"]+"."+t["name"]).casefold()
    om={key(t):t for t in old["tables"]}; nm={key(t):t for t in new["tables"]}
    added=sorted(set(nm)-set(om)); removed=sorted(set(om)-set(nm)); changed=[]
    for k in sorted(set(om)&set(nm)):
        a,b=om[k],nm[k]; ac={c["name"].casefold():c for c in a["columns"]}; bc={c["name"].casefold():c for c in b["columns"]}
        addc=sorted(set(bc)-set(ac)); delc=sorted(set(ac)-set(bc))
        types=sorted(c for c in set(ac)&set(bc) if ac[c]["type"].casefold()!=bc[c]["type"].casefold())
        nulls=sorted(c for c in set(ac)&set(bc) if ac[c].get("nullable")!=bc[c].get("nullable"))
        if addc or delc or types or nulls:
            changed.append({"table":b["name"],"schema":b["schema"],"added_columns":addc,"removed_columns":delc,"type_changes":[{"column":c,"before":ac[c]["type"],"after":bc[c]["type"]} for c in types],"nullability_changes":[{"column":c,"before":ac[c].get("nullable"),"after":bc[c].get("nullable")} for c in nulls]})
    risk="high" if removed or any(x["removed_columns"] for x in changed) else ("medium" if changed else "low")
    return {"provider":provider.lower(),"added_tables":added,"removed_tables":removed,"changed_tables":changed,"risk":risk,"warnings":old["warnings"]+new["warnings"]}
def analyze_airflow_dag(dag: dict[str,Any]):
    if not isinstance(dag,dict): raise ValueError("Airflow DAG export must be a JSON object")
    tasks=dag.get("tasks",[])
    if not isinstance(tasks,list) or len(tasks)>MAX_OBJECTS: raise ValueError("tasks must be a bounded list")
    nodes=[]; edges=[]; ids=set()
    for task in tasks:
        if not isinstance(task,dict): continue
        tid=_txt(task.get("task_id") or task.get("id"),300)
        if not tid or tid in ids: continue
        ids.add(tid); nodes.append({"id":tid,"operator":_txt(task.get("operator") or task.get("class_name") or "unknown",300)})
    unresolved=set()
    for task in tasks:
        if not isinstance(task,dict): continue
        tid=_txt(task.get("task_id") or task.get("id"),300)
        if tid not in ids: continue
        upstream=task.get("upstream_task_ids",task.get("upstream",[]))
        if not isinstance(upstream,list): continue
        for parent in upstream:
            parent=_txt(parent,300)
            if parent in ids: edges.append({"source":parent,"target":tid,"kind":"airflow_task_dependency"})
            elif parent: unresolved.add(parent)
    return {"provider":"apache_airflow","dag_id":_txt(dag.get("dag_id") or dag.get("name"),300),"task_count":len(nodes),"nodes":nodes,"edges":edges,"unresolved_dependencies":sorted(unresolved),"warnings":["DAG export only; scheduling, task execution and runtime data lineage were not checked."]}
