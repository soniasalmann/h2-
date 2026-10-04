r"""
CyberGuard AI - LangGraph Pipeline Builder.
Assembles the multi-agent incident response state graph with autonomous severity-based branching:
  Ingest -> Detect ->(conditional)-> Classify ->(conditional severity branch)-> Response -> Report
                                              \-> (LOW/MED) -----------------------------> Report
"""

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from agents.state import AgentState
from agents.nodes import (
    ingest_agent,
    detect_agent,
    classify_agent,
    response_agent,
    report_agent,
)


def should_classify(state: AgentState) -> str:
    """Route from detect: proceed to classify if anomalies/patterns found, else finish."""
    return "classify" if state.get("anomalies") else END


def route_after_classify(state: AgentState) -> str:
    """
    Severity-based conditional router:
    - If CRITICAL or HIGH threats exist -> Route to 'response' (Response Agent)
    - If only LOW or MEDIUM threats exist -> Route directly to 'report' (Report Agent)
    - If no threats exist -> END
    """
    threats = state.get("classified_threats", [])
    has_critical_or_high = state.get("has_critical_threats", False) or any(
        t.get("severity") in ("critical", "high") for t in threats
    )

    if has_critical_or_high:
        return "response"
    elif state.get("needs_report") or len(threats) > 0:
        return "report"
    return END


def build_graph(model_name: str = "llama3.1:8b", use_memory: bool = True):
    """
    Build and compile the CyberGuard AI LangGraph pipeline.

    Flow:
      ingest → detect →(conditional)→ classify →(severity router)
                                                  ├── [CRITICAL / HIGH] → response → report → END
                                                  └── [LOW / MEDIUM]    ───────────→ report → END
    """
    def ingest_fn(state):   return ingest_agent(state,   model_name)
    def detect_fn(state):   return detect_agent(state,   model_name)
    def classify_fn(state): return classify_agent(state, model_name)
    def response_fn(state): return response_agent(state, model_name)
    def report_fn(state):   return report_agent(state,   model_name)

    graph = StateGraph(AgentState)

    graph.add_node("ingest",   ingest_fn)
    graph.add_node("detect",   detect_fn)
    graph.add_node("classify", classify_fn)
    graph.add_node("response", response_fn)
    graph.add_node("report",   report_fn)

    graph.set_entry_point("ingest")
    graph.add_edge("ingest", "detect")

    graph.add_conditional_edges(
        "detect",
        should_classify,
        {
            "classify": "classify",
            END: END,
        }
    )

    graph.add_conditional_edges(
        "classify",
        route_after_classify,
        {
            "response": "response",
            "report": "report",
            END: END,
        }
    )

    graph.add_edge("response", "report")
    graph.add_edge("report", END)

    checkpointer = MemorySaver() if use_memory else None
    return graph.compile(checkpointer=checkpointer)
