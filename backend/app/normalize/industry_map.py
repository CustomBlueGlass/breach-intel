"""
Maps messy free-text industry/sector mentions to a small controlled
taxonomy, so analytics ("breaches by industry") aren't fragmented across
fifty near-duplicate strings like "Healthcare", "healthcare provider",
"Hospital system", "Medical/Health".
"""
INDUSTRY_TAXONOMY = {
    "healthcare": ["health", "hospital", "medical", "clinic", "pharma", "dental"],
    "financial_services": ["bank", "credit union", "financial", "insurance", "fintech", "lending"],
    "education": ["school", "university", "college", "k-12", "education"],
    "government": ["county", "city of", "municipal", "state agency", "federal agency", "government"],
    "retail": ["retail", "ecommerce", "e-commerce", "store", "shop"],
    "technology": ["software", "saas", "technology", "tech company", "it services"],
    "manufacturing": ["manufactur", "industrial", "factory"],
    "energy_utilities": ["energy", "utility", "utilities", "power", "oil", "gas"],
    "legal_services": ["law firm", "legal", "attorney"],
    "hospitality": ["hotel", "restaurant", "hospitality", "casino"],
    "transportation": ["airline", "shipping", "logistics", "transportation", "trucking"],
    "nonprofit": ["nonprofit", "non-profit", "charity", "ngo"],
}


def normalize_industry(raw: str | None) -> str | None:
    if not raw:
        return None
    lower = raw.lower()
    for canonical, keywords in INDUSTRY_TAXONOMY.items():
        if any(kw in lower for kw in keywords):
            return canonical
    return "other"
