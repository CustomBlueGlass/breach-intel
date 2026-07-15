"""Normalize free-text location mentions to (country, region_state)."""
US_STATE_ABBR = {
    "alabama": "AL", "alaska": "AK", "arizona": "AZ", "arkansas": "AR", "california": "CA",
    "colorado": "CO", "connecticut": "CT", "delaware": "DE", "florida": "FL", "georgia": "GA",
    "hawaii": "HI", "idaho": "ID", "illinois": "IL", "indiana": "IN", "iowa": "IA",
    "kansas": "KS", "kentucky": "KY", "louisiana": "LA", "maine": "ME", "maryland": "MD",
    "massachusetts": "MA", "michigan": "MI", "minnesota": "MN", "mississippi": "MS",
    "missouri": "MO", "montana": "MT", "nebraska": "NE", "nevada": "NV", "new hampshire": "NH",
    "new jersey": "NJ", "new mexico": "NM", "new york": "NY", "north carolina": "NC",
    "north dakota": "ND", "ohio": "OH", "oklahoma": "OK", "oregon": "OR", "pennsylvania": "PA",
    "rhode island": "RI", "south carolina": "SC", "south dakota": "SD", "tennessee": "TN",
    "texas": "TX", "utah": "UT", "vermont": "VT", "virginia": "VA", "washington": "WA",
    "west virginia": "WV", "wisconsin": "WI", "wyoming": "WY",
}


def normalize_location(raw: str | None) -> tuple[str | None, str | None]:
    """Returns (country, region_state). Defaults country to 'US' when a US
    state is recognized; otherwise leaves country unset for the correlation
    layer to infer from source (e.g. ICO/NCSC/EDPB rows default to UK/EU)."""
    if not raw:
        return None, None
    lower = raw.strip().lower()
    if lower in US_STATE_ABBR:
        return "US", US_STATE_ABBR[lower]
    if lower.upper() in US_STATE_ABBR.values():
        return "US", lower.upper()
    return None, raw.strip()
