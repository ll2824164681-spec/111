import json
from typing import TypedDict, List
from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage, AIMessage

# ------------------ 状态定义 ------------------
class AuditState(TypedDict):
    resources: dict          # 原始资源快照
    findings: List[dict]     # 发现的风险项
    clarified_findings: List[dict]  # 经长链推理后的风险项
    report: str              # 最终报告
    compliance_score: float  # 合规评分

# ------------------ Agent 1: 数据采集 & 规则扫描 ------------------
def data_collection_and_scan(state: AuditState):
    # 模拟从云API获取资源数据
    resources = {
        "s3_buckets": [{"name": "bucket-a", "public": True}],
        "iam_users": [{"name": "alice", "mfa": False, "policies": ["Admin"]}]
    }
    state["resources"] = resources
    
    # 确定性规则扫描：发现明显风险
    findings = []
    for bucket in resources["s3_buckets"]:
        if bucket["public"]:
            findings.append({"resource": bucket["name"], "issue": "公开访问", "severity": "高"})
    for user in resources["iam_users"]:
        if not user["mfa"]:
            findings.append({"resource": user["name"], "issue": "未启用MFA", "severity": "高"})
        if "Admin" in user["policies"]:
            # 模糊问题交给长链推理
            findings.append({"resource": user["name"], "issue": "持有管理员权限", "severity": "待评估",
                             "need_deep_reasoning": True})
    state["findings"] = findings
    return state

# ------------------ Agent 2: 长链推理节点（核心） ------------------
def deep_reasoning(state: AuditState):
    """对模糊策略进行多步推理，输出风险定级和建议"""
    llm_output = None  # 实际调用LLM
    # 示例：对于需要深度推理的项，构造包含上下文的提示链
    for finding in state["findings"]:
        if finding.get("need_deep_reasoning"):
            # 第一步：获取相关附加信息（模拟工具调用）
            extra_context = query_last_used_time(finding["resource"])  # 比如90天未使用
            
            # 第二步：多步推理链
            reasoning_prompt = f"""
            用户 {finding['resource']} 具有Admin权限。
            该用户最近活动时间: {extra_context}。
            业务部门要求所有用户遵循最小权限原则。
            请逐步推理：
            1. 该权限是否为当前职责必需？
            2. 若长期未使用，按公司安全政策应降权或回收。
            3. 给出最终风险等级（低/中/高）和修复建议。
            """
            # 调用LLM得到结构化结果
            # reasoning_result = llm.invoke(reasoning_prompt)
            reasoning_result = {"risk": "中", "suggestion": "降级为ReadOnly，90天未使用建议回收"}
            
            # 更新发现项
            finding["severity"] = reasoning_result["risk"]
            finding["suggestion"] = reasoning_result["suggestion"]
            finding.pop("need_deep_reasoning")
    state["clarified_findings"] = state["findings"]
    return state

def query_last_used_time(username):
    # 模拟调用IAM API获取最后使用时间
    return "最近一次使用在120天前"

# ------------------ Agent 3: 评估 & 报告生成 ------------------
def evaluate_and_report(state: AuditState):
    # 计算合规分，生成报告
    total = len(state["clarified_findings"])
    high_risk = sum(1 for f in state["clarified_findings"] if f["severity"] == "高")
    score = max(0, 100 - high_risk * 20)
    state["compliance_score"] = score
    
    # 生成报告摘要（实际中调用LLM生成格式化报告）
    report_lines = ["# 合规审计报告", f"总体评分: {score}/100", "## 风险项"]
    for f in state["clarified_findings"]:
        report_lines.append(f"- {f['resource']}: {f['issue']} [严重性: {f['severity']}]")
        if "suggestion" in f:
            report_lines.append(f"  建议: {f['suggestion']}")
    state["report"] = "\n".join(report_lines)
    return state

# ------------------ Agent 4: 自动修复（闭环） ------------------
def auto_remediate(state: AuditState):
    """对能够安全自动修复的项目执行修复并验证"""
    for f in state["clarified_findings"]:
        if f["issue"] == "公开访问" and f["severity"] == "高":
            # 模拟调用API关闭公共访问
            print(f"正在修复: 关闭 {f['resource']} 的公开访问...")
            # 验证修复结果（实际会二次查询）
            f["status"] = "已自动修复"
    return state

# ------------------ 构建多Agent图 ------------------
workflow = StateGraph(AuditState)

workflow.add_node("scanner", data_collection_and_scan)
workflow.add_node("deep_reasoning", deep_reasoning)
workflow.add_node("evaluator", evaluate_and_report)
workflow.add_node("remediator", auto_remediate)

workflow.set_entry_point("scanner")
workflow.add_edge("scanner", "deep_reasoning")     # 扫描后进入长链推理
workflow.add_edge("deep_reasoning", "evaluator")   # 推理后评估
workflow.add_edge("evaluator", "remediator")       # 评估后尝试修复
workflow.add_edge("remediator", END)

app = workflow.compile()

# 执行审计
initial_state = {"resources": {}, "findings": [], "clarified_findings": [], "report": "", "compliance_score": 0}
result = app.invoke(initial_state)

print(result["report"])
print(f"最终合规评分: {result['compliance_score']}")