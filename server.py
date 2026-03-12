import os
import json
import httpx
from datetime import datetime, timedelta
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

load_dotenv()

OKTA_DOMAIN = os.getenv("OKTA_DOMAIN")
OKTA_API_TOKEN = os.getenv("OKTA_API_TOKEN")

mcp = FastMCP("okta")


def _get_headers():
    return {
        "Authorization": f"SSWS {OKTA_API_TOKEN}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }


@mcp.tool()
def create_user(first_name: str, last_name: str, email: str, department: str) -> dict:
    """Create a new Okta user and activate them."""
    payload = {
        "profile": {
            "firstName": first_name,
            "lastName": last_name,
            "email": email,
            "login": email,
            "department": department
        },
        "credentials": {
            "password": {"hook": {"type": "default"}}
        }
    }
    r = httpx.post(f"{OKTA_DOMAIN}/api/v1/users?activate=true",
                   headers=_get_headers(), json=payload)
    return r.json()


@mcp.tool()
def deactivate_user(email: str) -> dict:
    """Deactivate an Okta user by email."""
    r = httpx.get(f"{OKTA_DOMAIN}/api/v1/users/{email}", headers=_get_headers())
    if r.status_code != 200:
        return {"error": f"User {email} not found", "errorCode": "E0000007"}
    user_id = r.json()["id"]
    httpx.post(f"{OKTA_DOMAIN}/api/v1/users/{user_id}/lifecycle/deactivate",
               headers=_get_headers())
    return {"status": "DEPROVISIONED", "userId": user_id}


@mcp.tool()
def list_inactive_users(days_threshold: int = 90) -> list:
    """List active users who have not logged in within the given number of days."""
    cutoff = (datetime.now() - timedelta(days=days_threshold)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    r = httpx.get(f"{OKTA_DOMAIN}/api/v1/users?filter=status+eq+%22ACTIVE%22&limit=200",
                  headers=_get_headers())
    if r.status_code != 200:
        return [{"error": r.text}]
    users = r.json()
    inactive = []
    for user in users:
        last_login = user.get("lastLogin")
        if last_login and last_login < cutoff:
            inactive.append({
                "email": user["profile"]["login"],
                "name": f"{user['profile']['firstName']} {user['profile']['lastName']}",
                "department": user["profile"].get("department", "N/A"),
                "lastLogin": last_login,
                "daysSinceLogin": (datetime.now() - datetime.fromisoformat(last_login[:19])).days
            })
        elif not last_login:
            inactive.append({
                "email": user["profile"]["login"],
                "name": f"{user['profile']['firstName']} {user['profile']['lastName']}",
                "department": user["profile"].get("department", "N/A"),
                "lastLogin": "Never",
                "daysSinceLogin": 9999
            })
    return sorted(inactive, key=lambda x: x["daysSinceLogin"], reverse=True)


@mcp.tool()
def assign_to_group(email: str, group_name: str) -> dict:
    """Assign an Okta user to a group by group name."""
    r = httpx.get(f"{OKTA_DOMAIN}/api/v1/users/{email}", headers=_get_headers())
    if r.status_code != 200:
        return {"error": f"User {email} not found", "errorCode": "E0000007"}
    user_id = r.json()["id"]
    r2 = httpx.get(f"{OKTA_DOMAIN}/api/v1/groups?q={group_name}", headers=_get_headers())
    groups = r2.json()
    if not groups:
        return {"error": f"Group {group_name} not found", "errorCode": "E0000007"}
    group_id = groups[0]["id"]
    httpx.put(f"{OKTA_DOMAIN}/api/v1/groups/{group_id}/users/{user_id}",
              headers=_get_headers())
    return {"userId": user_id, "email": email, "group": group_name, "status": "ASSIGNED"}


@mcp.tool()
def check_mfa(email: str) -> dict:
    """Check MFA enrollment status for an Okta user."""
    r = httpx.get(f"{OKTA_DOMAIN}/api/v1/users/{email}", headers=_get_headers())
    if r.status_code != 200:
        return {"error": f"User {email} not found", "errorCode": "E0000007"}
    user_data = r.json()
    user_id = user_data["id"]
    status = user_data["status"]
    r2 = httpx.get(f"{OKTA_DOMAIN}/api/v1/users/{user_id}/factors", headers=_get_headers())
    factors = [f["factorType"] for f in r2.json()] if r2.status_code == 200 else []
    enrolled = len(factors) > 0
    return {
        "email": email,
        "mfa_enrolled": enrolled,
        "factors": factors,
        "status": status,
        "risk_level": "HIGH" if not enrolled and status == "ACTIVE" else "LOW"
    }


if __name__ == "__main__":
    mcp.run()
