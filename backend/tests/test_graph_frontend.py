from pathlib import Path

def test_interactive_graph_controls_and_accessibility_are_present():
    html = (Path(__file__).resolve().parents[2] / "frontend" / "index.html").read_text(encoding="utf-8")
    for marker in (
        'id="graphFilter"', 'id="graphZoomIn"', 'id="graphZoomOut"',
        'id="graphFit"', 'id="graphReset"', 'aria-label="Filter graph objects"',
        'function bindGraphControls()', 'function renderGraph(data)',
        'is-related', 'Column-level lineage',
    ):
        assert marker in html

def test_graph_uses_actual_analysis_relationship_and_lineage_data():
    html = (Path(__file__).resolve().parents[2] / "frontend" / "index.html").read_text(encoding="utf-8")
    assert "data.graph" in html
    assert "data.relationships" in html
    assert "data.column_lineage" in html
    assert "data.unresolved_references" in html
