#!/usr/bin/env python3
"""Generate the samples/ multi-language CVE fixture dataset."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NOW = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.lstrip("\n") if text.startswith("\n") else text, encoding="utf-8")
    if not text.endswith("\n"):
        path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def blueprint(
    *,
    cve_id: str,
    score: float,
    vector: str,
    name: str,
    purl: str,
    cpe: str,
    cwe_ids: list[str],
    exploit_type: str,
    features: list[str],
    conditions: list[dict],
    attack_steps: list[str],
    attacker_inputs: list[str],
    sinks: list[str],
    advisories: list[str],
    fixed_versions: list[str],
    mitigations: list[dict],
) -> dict:
    return {
        "schema_version": "1.0",
        "cve_id": cve_id,
        "cvss": {"score": score, "vector": vector},
        "affected_components": [{"name": name, "purl": purl, "cpe": cpe}],
        "cwe_ids": cwe_ids,
        "capec_ids": [],
        "exploit_type": exploit_type,
        "affected_features": features,
        "conditions": conditions,
        "attack_steps": attack_steps,
        "attacker_inputs": attacker_inputs,
        "upstream_artifacts": {
            "functions": sinks,
            "files": [],
            "fix_commits": [],
            "advisories": advisories,
        },
        "remediation": {
            "fixed_versions": fixed_versions,
            "patch_indicators": [],
            "security_advisories": advisories,
        },
        "mitigations": mitigations,
        "references": {
            "cwe_ids": cwe_ids,
            "capec_ids": [],
            "osv_ids": [],
            "kev": False,
        },
        "confidence": "high",
        "created_at": NOW,
    }


def sbom(cve_id: str, name: str, version: str, purl: str) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": [
            {"bom-ref": "c1", "type": "library", "name": name, "version": version, "purl": purl}
        ],
        "vulnerabilities": [{"id": cve_id, "affects": [{"ref": "c1"}]}],
    }


def cond(ctype: str, value: str) -> dict:
    return {"type": ctype, "value": value, "source": "sample fixture", "confidence": "high"}


def mit(text: str, hints: list[str], strength: str = "high") -> dict:
    return {
        "mitigation": text,
        "source": "sample fixture",
        "confidence": "high",
        "strength": strength,
        "detection_hints": hints,
    }


# ─── Python ───────────────────────────────────────────────────────────────────

def python_samples() -> None:
    # 1) PyYAML RCE
    case = ROOT / "python" / "CVE-2020-14343-pyyaml"
    purl = "pkg:pypi/pyyaml@5.3.1"
    write_json(
        case / "blueprint.json",
        blueprint(
            cve_id="CVE-2020-14343",
            score=9.8,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            name="PyYAML",
            purl=purl,
            cpe="cpe:2.3:a:pyyaml:pyyaml::::::*",
            cwe_ids=["CWE-20"],
            exploit_type="deserialization leading to remote code execution",
            features=["YAML deserialization with FullLoader / full_load"],
            conditions=[
                cond("network_access", "attacker can supply YAML over HTTP"),
                cond("privilege_required", "none"),
                cond("user_interaction", "none"),
                cond("dependency_reachability", "app calls yaml.full_load or FullLoader"),
                cond("feature_exposed_by_component", "YAML parsing of untrusted input"),
                cond("configuration_requirement", "uses FullLoader / full_load instead of SafeLoader"),
            ],
            attack_steps=[
                "Send crafted YAML with python/object/new to an HTTP endpoint",
                "Endpoint parses with yaml.full_load / FullLoader",
                "Arbitrary object construction executes attacker code",
            ],
            attacker_inputs=["malicious YAML document"],
            sinks=["yaml.full_load", "yaml.load", "FullLoader"],
            advisories=[
                "https://nvd.nist.gov/vuln/detail/CVE-2020-14343",
                "https://github.com/advisories/GHSA-8q59-q68h-6hv4",
            ],
            fixed_versions=["5.4"],
            mitigations=[
                mit("upgrade to PyYAML >= 5.4", ["pyyaml>=5.4"]),
                mit("use yaml.safe_load / SafeLoader", ["safe_load", "SafeLoader"]),
            ],
        ),
    )
    write_json(case / "sbom.json", sbom("CVE-2020-14343", "pyyaml", "5.3.1", purl))
    write(case / "app/requirements.txt", "PyYAML==5.3.1\nFlask==2.3.3\n")
    write(
        case / "app/app.py",
        '''
"""Vulnerable: untrusted YAML via yaml.full_load / FullLoader."""
from flask import Flask, request
import yaml

app = Flask(__name__)


@app.post("/config")
def load_config():
    raw = request.data.decode("utf-8")
    data = yaml.full_load(raw)
    return {"ok": True, "keys": list(data.keys()) if isinstance(data, dict) else []}


def parse_user_yaml(payload: str):
    return yaml.load(payload, Loader=yaml.FullLoader)


if __name__ == "__main__":
    app.run(port=5001)
''',
    )
    write(
        case / "README.md",
        """# CVE-2020-14343 — PyYAML

Vulnerable sample using `yaml.full_load` / `FullLoader` on request bodies.

```bash
pip install -r app/requirements.txt
PYTHONPATH=. python -m core.pipeline  # or POST /api/v1/analyze with sbom.json
```
""",
    )

    # 2) PyJWT algorithm confusion
    case = ROOT / "python" / "CVE-2022-29217-pyjwt"
    purl = "pkg:pypi/pyjwt@1.7.1"
    write_json(
        case / "blueprint.json",
        blueprint(
            cve_id="CVE-2022-29217",
            score=7.4,
            vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
            name="PyJWT",
            purl=purl,
            cpe="cpe:2.3:a:pyjwt_project:pyjwt::::::*",
            cwe_ids=["CWE-327"],
            exploit_type="JWT algorithm confusion / key confusion",
            features=["JWT decode without restricting algorithms"],
            conditions=[
                cond("network_access", "attacker can supply a JWT"),
                cond("privilege_required", "none"),
                cond("user_interaction", "none"),
                cond("dependency_reachability", "app calls jwt.decode on attacker tokens"),
                cond("configuration_requirement", "decode without algorithms= allow-list (or alg=none issues)"),
            ],
            attack_steps=[
                "Obtain or forge a JWT with unexpected alg",
                "Submit token to an endpoint that calls jwt.decode without algorithms restriction",
                "Verifier accepts forged token",
            ],
            attacker_inputs=["forged JWT"],
            sinks=["jwt.decode", "PyJWT.decode"],
            advisories=[
                "https://nvd.nist.gov/vuln/detail/CVE-2022-29217",
                "https://github.com/advisories/GHSA-ffqj-6fqr-9h24",
            ],
            fixed_versions=["2.4.0"],
            mitigations=[
                mit("upgrade to PyJWT >= 2.4.0", ["PyJWT>=2.4.0"]),
                mit("always pass algorithms=[...] to jwt.decode", ["algorithms="]),
            ],
        ),
    )
    write_json(case / "sbom.json", sbom("CVE-2022-29217", "pyjwt", "1.7.1", purl))
    write(case / "app/requirements.txt", "PyJWT==1.7.1\nFlask==2.3.3\n")
    write(
        case / "app/app.py",
        '''
"""Vulnerable: jwt.decode without algorithms allow-list."""
from flask import Flask, request
import jwt

app = Flask(__name__)
SECRET = "dev-secret"


@app.get("/profile")
def profile():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    # Vulnerable pattern for older PyJWT: no algorithms= restriction
    claims = jwt.decode(token, SECRET, verify=True)
    return {"user": claims.get("sub")}


if __name__ == "__main__":
    app.run(port=5002)
''',
    )
    write(case / "README.md", "# CVE-2022-29217 — PyJWT\n\nJWT decode without `algorithms=` allow-list.\n")

    # 3) Pillow path traversal / buffer issues via Image.open on untrusted path
    case = ROOT / "python" / "CVE-2023-50447-pillow"
    purl = "pkg:pypi/pillow@10.0.0"
    write_json(
        case / "blueprint.json",
        blueprint(
            cve_id="CVE-2023-50447",
            score=8.1,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
            name="Pillow",
            purl=purl,
            cpe="cpe:2.3:a:python:pillow::::::*",
            cwe_ids=["CWE-22"],
            exploit_type="arbitrary code / environment control via crafted image environment keys",
            features=["PIL.Image.open processing of attacker-controlled images"],
            conditions=[
                cond("network_access", "attacker can upload or point to an image"),
                cond("user_interaction", "may require opening/processing the image"),
                cond("dependency_reachability", "app calls PIL.Image.open on untrusted image bytes/path"),
                cond("feature_exposed_by_component", "image upload / thumbnail generation"),
            ],
            attack_steps=[
                "Upload a crafted image",
                "Server opens it with PIL.Image.open",
                "Vulnerable Pillow behavior is triggered during processing",
            ],
            attacker_inputs=["crafted image file"],
            sinks=["Image.open", "PIL.Image.open"],
            advisories=[
                "https://nvd.nist.gov/vuln/detail/CVE-2023-50447",
                "https://github.com/advisories/GHSA-3f63-hfp8-52jq",
            ],
            fixed_versions=["10.2.0"],
            mitigations=[
                mit("upgrade Pillow to >= 10.2.0", ["Pillow>=10.2.0"]),
                mit("validate/sanitize uploaded image content-type and size", ["content_type"]),
            ],
        ),
    )
    write_json(case / "sbom.json", sbom("CVE-2023-50447", "pillow", "10.0.0", purl))
    write(case / "app/requirements.txt", "Pillow==10.0.0\nFlask==2.3.3\n")
    write(
        case / "app/app.py",
        '''
"""Vulnerable: Image.open on attacker-uploaded files."""
from pathlib import Path
from flask import Flask, request
from PIL import Image

app = Flask(__name__)
UPLOAD = Path("/tmp/sample-pillow-uploads")
UPLOAD.mkdir(parents=True, exist_ok=True)


@app.post("/thumb")
def thumb():
    f = request.files["file"]
    dest = UPLOAD / f.filename
    f.save(dest)
    img = Image.open(dest)  # sink
    img.thumbnail((64, 64))
    out = UPLOAD / f"thumb-{f.filename}"
    img.save(out)
    return {"thumb": str(out)}


if __name__ == "__main__":
    app.run(port=5003)
''',
    )
    write(case / "README.md", "# CVE-2023-50447 — Pillow\n\n`PIL.Image.open` on uploaded files.\n")


# ─── Java ─────────────────────────────────────────────────────────────────────

def java_samples() -> None:
    # 1) Log4Shell
    case = ROOT / "java" / "CVE-2021-44228-log4j"
    purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    write_json(
        case / "blueprint.json",
        blueprint(
            cve_id="CVE-2021-44228",
            score=10.0,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            name="log4j-core",
            purl=purl,
            cpe="cpe:2.3:a:apache:log4j::::::*",
            cwe_ids=["CWE-917", "CWE-502"],
            exploit_type="JNDI injection via Log4j message lookup (Log4Shell)",
            features=["logging of untrusted input with message lookups enabled"],
            conditions=[
                cond("network_access", "attacker can influence a logged string"),
                cond("privilege_required", "none"),
                cond("user_interaction", "none"),
                cond("dependency_reachability", "app or framework logs attacker-controlled data via Log4j"),
                cond("configuration_requirement", "message lookups / JNDI resolution enabled (default on vulnerable versions)"),
            ],
            attack_steps=[
                "Send ${jndi:ldap://...} in a header or parameter that is logged",
                "Log4j interpolates the lookup and contacts attacker LDAP",
                "Remote class loading / RCE",
            ],
            attacker_inputs=["HTTP header or body containing JNDI lookup"],
            sinks=["Logger.info", "Logger.error", "Logger.warn", "log4j"],
            advisories=[
                "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                "https://logging.apache.org/log4j/2.x/security.html",
            ],
            fixed_versions=["2.17.0"],
            mitigations=[
                mit("upgrade log4j-core to >= 2.17.0", ["log4j-core"]),
                mit("set log4j2.formatMsgNoLookups=true where applicable", ["formatMsgNoLookups"]),
            ],
        ),
    )
    write_json(case / "sbom.json", sbom("CVE-2021-44228", "log4j-core", "2.14.1", purl))
    write(
        case / "app/pom.xml",
        """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>samples</groupId>
  <artifactId>log4shell-demo</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
  </dependencies>
</project>
""",
    )
    write(
        case / "app/src/main/java/samples/App.java",
        """package samples;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Vulnerable: logs attacker-controlled input with Log4j 2.14.1. */
public class App {
    private static final Logger log = LogManager.getLogger(App.class);

    public static void handle(String userAgent) {
        log.info("Request from {}", userAgent); // sink for Log4Shell-style input
    }

    public static void main(String[] args) {
        String ua = args.length > 0 ? args[0] : "safe";
        handle(ua);
    }
}
""",
    )
    write(case / "README.md", "# CVE-2021-44228 — Log4j\n\nLogs untrusted input with log4j-core 2.14.1.\n")

    # 2) Jackson polymorphic deserialization
    case = ROOT / "java" / "CVE-2019-12384-jackson"
    purl = "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.9"
    write_json(
        case / "blueprint.json",
        blueprint(
            cve_id="CVE-2019-12384",
            score=8.1,
            vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            name="jackson-databind",
            purl=purl,
            cpe="cpe:2.3:a:fasterxml:jackson-databind::::::*",
            cwe_ids=["CWE-502"],
            exploit_type="polymorphic deserialization gadget chain",
            features=["ObjectMapper.readValue with default typing / polymorphic types"],
            conditions=[
                cond("network_access", "attacker can submit JSON"),
                cond("dependency_reachability", "app deserializes untrusted JSON with jackson-databind"),
                cond("configuration_requirement", "default typing or polymorphic type handling enabled"),
            ],
            attack_steps=[
                "Send JSON with attacker-controlled @type / type id",
                "ObjectMapper.readValue instantiates a gadget class",
                "Side effects lead to RCE or info disclosure",
            ],
            attacker_inputs=["malicious JSON"],
            sinks=["ObjectMapper.readValue", "readValue"],
            advisories=["https://nvd.nist.gov/vuln/detail/CVE-2019-12384"],
            fixed_versions=["2.9.9.3"],
            mitigations=[
                mit("upgrade jackson-databind", ["jackson-databind"]),
                mit("disable default typing; use allow-lists", ["activateDefaultTyping"]),
            ],
        ),
    )
    write_json(case / "sbom.json", sbom("CVE-2019-12384", "jackson-databind", "2.9.9", purl))
    write(
        case / "app/pom.xml",
        """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>samples</groupId>
  <artifactId>jackson-demo</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.9.9</version>
    </dependency>
  </dependencies>
</project>
""",
    )
    write(
        case / "app/src/main/java/samples/JsonApi.java",
        """package samples;

import com.fasterxml.jackson.databind.ObjectMapper;

/** Vulnerable: ObjectMapper.readValue on untrusted JSON with default typing. */
public class JsonApi {
    private final ObjectMapper mapper = new ObjectMapper();

    public JsonApi() {
        // Dangerous configuration pattern for the fixture
        mapper.enableDefaultTyping();
    }

    public Object parse(String body) throws Exception {
        return mapper.readValue(body, Object.class); // sink
    }
}
""",
    )
    write(case / "README.md", "# CVE-2019-12384 — Jackson\n\n`ObjectMapper.readValue` with default typing.\n")

    # 3) Spring4Shell-ish / Spring expression on request
    case = ROOT / "java" / "CVE-2022-22965-spring"
    purl = "pkg:maven/org.springframework/spring-beans@5.3.17"
    write_json(
        case / "blueprint.json",
        blueprint(
            cve_id="CVE-2022-22965",
            score=9.8,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            name="spring-beans",
            purl=purl,
            cpe="cpe:2.3:a:vmware:spring_framework::::::*",
            cwe_ids=["CWE-94"],
            exploit_type="data binding RCE (Spring4Shell class of issues)",
            features=["Spring MVC data binding on untrusted request parameters"],
            conditions=[
                cond("network_access", "attacker can send HTTP parameters"),
                cond("dependency_reachability", "Spring MVC controller binds request data to objects"),
                cond("configuration_requirement", "vulnerable Spring version on JDK 9+ with specific packaging"),
            ],
            attack_steps=[
                "Send crafted request parameters targeting class loader properties",
                "Spring data binder applies properties",
                "Webapp is overwritten / RCE achieved",
            ],
            attacker_inputs=["HTTP form / query parameters"],
            sinks=["WebDataBinder", "ServletRequestDataBinder", "DataBinder"],
            advisories=["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
            fixed_versions=["5.3.18"],
            mitigations=[
                mit("upgrade Spring Framework", ["spring-beans", "spring-webmvc"]),
                mit("disallow fields on binder", ["setDisallowedFields"]),
            ],
        ),
    )
    write_json(case / "sbom.json", sbom("CVE-2022-22965", "spring-beans", "5.3.17", purl))
    write(
        case / "app/pom.xml",
        """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>samples</groupId>
  <artifactId>spring4shell-demo</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-webmvc</artifactId>
      <version>5.3.17</version>
    </dependency>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-beans</artifactId>
      <version>5.3.17</version>
    </dependency>
  </dependencies>
</project>
""",
    )
    write(
        case / "app/src/main/java/samples/UserController.java",
        """package samples;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/** Fixture controller that binds untrusted form fields into a POJO. */
@Controller
public class UserController {

    public static class UserForm {
        public String name;
        public String email;
    }

    @PostMapping("/register")
    @ResponseBody
    public String register(UserForm form) {
        // Spring data binding of request params onto form (binder sink class of CVE)
        return "ok:" + form.name;
    }
}
""",
    )
    write(case / "README.md", "# CVE-2022-22965 — Spring\n\nSpring MVC data binding fixture (Spring4Shell class).\n")


# ─── npm ───────────────────────────────────────────────────────────────────────

def npm_samples() -> None:
    # 1) lodash template command injection
    case = ROOT / "npm" / "CVE-2021-23337-lodash"
    purl = "pkg:npm/lodash@4.17.20"
    write_json(
        case / "blueprint.json",
        blueprint(
            cve_id="CVE-2021-23337",
            score=7.2,
            vector="CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
            name="lodash",
            purl=purl,
            cpe="cpe:2.3:a:lodash:lodash::::::*",
            cwe_ids=["CWE-94"],
            exploit_type="command injection via lodash template",
            features=["_.template with attacker-controlled template source"],
            conditions=[
                cond("network_access", "attacker can supply template text"),
                cond("dependency_reachability", "app calls _.template on untrusted input"),
            ],
            attack_steps=[
                "Submit a malicious lodash template string",
                "Server compiles it with _.template",
                "Injected JS runs in the Node process",
            ],
            attacker_inputs=["template string"],
            sinks=["_.template", "lodash.template", "template"],
            advisories=[
                "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
                "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
            ],
            fixed_versions=["4.17.21"],
            mitigations=[
                mit("upgrade lodash to >= 4.17.21", ["lodash@>=4.17.21"]),
                mit("never compile untrusted templates", ["_.template"]),
            ],
        ),
    )
    write_json(case / "sbom.json", sbom("CVE-2021-23337", "lodash", "4.17.20", purl))
    write(
        case / "app/package.json",
        json.dumps(
            {
                "name": "lodash-template-demo",
                "version": "1.0.0",
                "private": True,
                "dependencies": {"lodash": "4.17.20", "express": "4.18.2"},
            },
            indent=2,
        )
        + "\n",
    )
    write(
        case / "app/index.js",
        """const express = require("express");
const _ = require("lodash");

const app = express();
app.use(express.text({ type: "*/*" }));

// Vulnerable: compile attacker-controlled template
app.post("/render", (req, res) => {
  const compiled = _.template(req.body); // sink
  res.type("text").send(compiled({ user: "guest" }));
});

app.listen(3001, () => console.log("lodash demo on :3001"));
""",
    )
    write(case / "README.md", "# CVE-2021-23337 — lodash\n\n`_.template` on request body.\n")

    # 2) node-ipc protestware / malicious versions (inclusion-style)
    case = ROOT / "npm" / "CVE-2022-23812-node-ipc"
    purl = "pkg:npm/node-ipc@10.1.1"
    write_json(
        case / "blueprint.json",
        blueprint(
            cve_id="CVE-2022-23812",
            score=9.8,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            name="node-ipc",
            purl=purl,
            cpe="cpe:2.3:a:node-ipc_project:node-ipc::::::*",
            cwe_ids=["CWE-506"],
            exploit_type="embedded malicious code (protestware) in published package versions",
            features=["loading / importing node-ipc malicious versions"],
            conditions=[
                cond("dependency_reachability", "application depends on and loads node-ipc"),
                cond("network_access", "geo-lookup may be performed at runtime"),
            ],
            attack_steps=[
                "Install affected node-ipc version",
                "Import or otherwise load the package",
                "Malicious payload overwrites files based on geo-IP",
            ],
            attacker_inputs=["N/A — payload is embedded in the package"],
            sinks=[],  # inclusion-style: presence/import is the signal
            advisories=[
                "https://nvd.nist.gov/vuln/detail/CVE-2022-23812",
                "https://github.com/advisories/GHSA-97m3-w2cp-4xx6",
            ],
            fixed_versions=["10.1.3"],
            mitigations=[
                mit("pin/remove malicious versions; upgrade past 10.1.2", ["node-ipc@10.1.3"]),
            ],
        ),
    )
    write_json(case / "sbom.json", sbom("CVE-2022-23812", "node-ipc", "10.1.1", purl))
    write(
        case / "app/package.json",
        json.dumps(
            {
                "name": "node-ipc-demo",
                "version": "1.0.0",
                "private": True,
                "dependencies": {"node-ipc": "10.1.1"},
            },
            indent=2,
        )
        + "\n",
    )
    write(
        case / "app/index.js",
        """// Inclusion-style fixture: importing the package is the activation signal.
// Do NOT install/run malicious versions on real hosts — this is for static assessment only.
const ipc = require("node-ipc");

ipc.config.id = "demo";
console.log("loaded node-ipc", typeof ipc);
""",
    )
    write(
        case / "README.md",
        """# CVE-2022-23812 — node-ipc

Inclusion / malicious-package sample. Prefer static assessment only; do not execute
compromised package versions on shared machines.
""",
    )

    # 3) underscore template injection
    case = ROOT / "npm" / "CVE-2021-23358-underscore"
    purl = "pkg:npm/underscore@1.12.0"
    write_json(
        case / "blueprint.json",
        blueprint(
            cve_id="CVE-2021-23358",
            score=7.2,
            vector="CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
            name="underscore",
            purl=purl,
            cpe="cpe:2.3:a:underscorejs:underscore::::::*",
            cwe_ids=["CWE-94"],
            exploit_type="arbitrary code execution via underscore template",
            features=["_.template compilation of untrusted strings"],
            conditions=[
                cond("network_access", "attacker can supply template content"),
                cond("dependency_reachability", "app calls _.template on untrusted input"),
            ],
            attack_steps=[
                "Submit a malicious underscore template",
                "Server compiles with _.template",
                "Injected code executes",
            ],
            attacker_inputs=["template string"],
            sinks=["_.template", "underscore.template", "template"],
            advisories=[
                "https://nvd.nist.gov/vuln/detail/CVE-2021-23358",
                "https://github.com/advisories/GHSA-cf4h-3jhx-xvhq",
            ],
            fixed_versions=["1.13.0-2", "1.12.1"],
            mitigations=[
                mit("upgrade underscore", ["underscore@>=1.12.1"]),
            ],
        ),
    )
    write_json(case / "sbom.json", sbom("CVE-2021-23358", "underscore", "1.12.0", purl))
    write(
        case / "app/package.json",
        json.dumps(
            {
                "name": "underscore-template-demo",
                "version": "1.0.0",
                "private": True,
                "dependencies": {"underscore": "1.12.0", "express": "4.18.2"},
            },
            indent=2,
        )
        + "\n",
    )
    write(
        case / "app/index.js",
        """const express = require("express");
const _ = require("underscore");

const app = express();
app.use(express.text({ type: "*/*" }));

app.post("/render", (req, res) => {
  const compiled = _.template(req.body); // sink
  res.type("text").send(compiled({ name: "guest" }));
});

app.listen(3002, () => console.log("underscore demo on :3002"));
""",
    )
    write(case / "README.md", "# CVE-2021-23358 — underscore\n\n`_.template` on request body.\n")


# ─── Go ────────────────────────────────────────────────────────────────────────

def go_samples() -> None:
    # 1) yaml.v3 DOS / parser issues
    case = ROOT / "go" / "CVE-2022-28948-yaml"
    purl = "pkg:golang/gopkg.in/yaml.v3@3.0.0"
    write_json(
        case / "blueprint.json",
        blueprint(
            cve_id="CVE-2022-28948",
            score=7.5,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            name="yaml.v3",
            purl=purl,
            cpe="cpe:2.3:a:yaml_project:yaml::::::*",
            cwe_ids=["CWE-835"],
            exploit_type="unbounded recursion / panic while parsing crafted YAML",
            features=["yaml.Unmarshal of untrusted documents"],
            conditions=[
                cond("network_access", "attacker can supply YAML"),
                cond("dependency_reachability", "app calls yaml.Unmarshal on attacker data"),
            ],
            attack_steps=[
                "Send crafted YAML",
                "Server calls yaml.Unmarshal",
                "Parser panics / DoS",
            ],
            attacker_inputs=["crafted YAML"],
            sinks=["yaml.Unmarshal", "Unmarshal"],
            advisories=["https://nvd.nist.gov/vuln/detail/CVE-2022-28948"],
            fixed_versions=["3.0.1"],
            mitigations=[mit("upgrade to gopkg.in/yaml.v3@v3.0.1+", ["yaml.v3"])],
        ),
    )
    write_json(case / "sbom.json", sbom("CVE-2022-28948", "yaml", "3.0.0", purl))
    write(
        case / "app/go.mod",
        """module samples/yaml-demo

go 1.21

require gopkg.in/yaml.v3 v3.0.0
""",
    )
    write(
        case / "app/main.go",
        """package main

import (
        "fmt"
        "io"
        "net/http"

        "gopkg.in/yaml.v3"
)

func handler(w http.ResponseWriter, r *http.Request) {
        body, _ := io.ReadAll(r.Body)
        var doc any
        if err := yaml.Unmarshal(body, &doc); err != nil { // sink
                http.Error(w, err.Error(), 400)
                return
        }
        fmt.Fprintf(w, "ok")
}

func main() {
        http.HandleFunc("/parse", handler)
        http.ListenAndServe(":8081", nil)
}
""",
    )
    write(case / "README.md", "# CVE-2022-28948 — gopkg.in/yaml.v3\n\n`yaml.Unmarshal` on request bodies.\n")

    # 2) golang.org/x/text vulnerability
    case = ROOT / "go" / "CVE-2021-38561-xtext"
    purl = "pkg:golang/golang.org/x/text@0.3.6"
    write_json(
        case / "blueprint.json",
        blueprint(
            cve_id="CVE-2021-38561",
            score=7.5,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            name="golang.org/x/text",
            purl=purl,
            cpe="cpe:2.3:a:golang:text::::::*",
            cwe_ids=["CWE-835"],
            exploit_type="panic / DoS via language tag parsing",
            features=["language.Parse / language tag handling of untrusted tags"],
            conditions=[
                cond("network_access", "attacker can supply Accept-Language or similar"),
                cond("dependency_reachability", "app parses untrusted language tags via x/text"),
            ],
            attack_steps=[
                "Send crafted language tag",
                "Server calls language.Parse",
                "Panic / DoS",
            ],
            attacker_inputs=["Accept-Language header"],
            sinks=["language.Parse", "Parse"],
            advisories=["https://nvd.nist.gov/vuln/detail/CVE-2021-38561"],
            fixed_versions=["0.3.7"],
            mitigations=[mit("upgrade golang.org/x/text", ["golang.org/x/text"])],
        ),
    )
    write_json(case / "sbom.json", sbom("CVE-2021-38561", "text", "0.3.6", purl))
    write(
        case / "app/go.mod",
        """module samples/xtext-demo

go 1.21

require golang.org/x/text v0.3.6
""",
    )
    write(
        case / "app/main.go",
        """package main

import (
        "fmt"
        "net/http"

        "golang.org/x/text/language"
)

func handler(w http.ResponseWriter, r *http.Request) {
        tag := r.Header.Get("Accept-Language")
        _, err := language.Parse(tag) // sink
        if err != nil {
                http.Error(w, err.Error(), 400)
                return
        }
        fmt.Fprint(w, "ok")
}

func main() {
        http.HandleFunc("/lang", handler)
        http.ListenAndServe(":8082", nil)
}
""",
    )
    write(case / "README.md", "# CVE-2021-38561 — golang.org/x/text\n\n`language.Parse` on Accept-Language.\n")

    # 3) gin path traversal (historical class) — use known CVE-2020-28483 for gin
    case = ROOT / "go" / "CVE-2020-28483-gin"
    purl = "pkg:golang/github.com/gin-gonic/gin@1.6.3"
    write_json(
        case / "blueprint.json",
        blueprint(
            cve_id="CVE-2020-28483",
            score=7.1,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L",
            name="gin",
            purl=purl,
            cpe="cpe:2.3:a:gin-gonic:gin::::::*",
            cwe_ids=["CWE-601"],
            exploit_type="open redirect / client exposure via unexpected handling of // in paths",
            features=["Gin router handling of attacker-controlled redirect / path input"],
            conditions=[
                cond("network_access", "attacker can trigger a redirect path"),
                cond("dependency_reachability", "app uses gin redirect helpers with untrusted input"),
            ],
            attack_steps=[
                "Craft a request that leads to Controllers redirecting with attacker input",
                "Client follows unexpected location",
            ],
            attacker_inputs=["path / redirect target"],
            sinks=["Redirect", "c.Redirect"],
            advisories=["https://nvd.nist.gov/vuln/detail/CVE-2020-28483"],
            fixed_versions=["1.7.0"],
            mitigations=[mit("upgrade gin to >= 1.7.0", ["github.com/gin-gonic/gin"])],
        ),
    )
    write_json(case / "sbom.json", sbom("CVE-2020-28483", "gin", "1.6.3", purl))
    write(
        case / "app/go.mod",
        """module samples/gin-demo

go 1.21

require github.com/gin-gonic/gin v1.6.3
""",
    )
    write(
        case / "app/main.go",
        """package main

import (
        "net/http"

        "github.com/gin-gonic/gin"
)

func main() {
        r := gin.Default()
        r.GET("/go", func(c *gin.Context) {
                target := c.Query("next")
                c.Redirect(http.StatusFound, target) // sink
        })
        r.Run(":8083")
}
""",
    )
    write(case / "README.md", "# CVE-2020-28483 — gin\n\n`c.Redirect` with query-controlled target.\n")


def write_root_readme() -> None:
    write(
        ROOT / "README.md",
        """# Sample CVE assessment dataset

Multi-language fixtures for exercising the SCA risk-rescoring pipeline.

## Layout

```text
samples/
  <language>/
    <CVE-ID>-<package>/
      blueprint.json   # component–CVE research blueprint
      sbom.json        # minimal CycloneDX SBOM for that finding
      app/             # small product-like code that uses the vulnerable package
      README.md
```

## Languages (3 CVEs each)

| Language | CVE folders |
|----------|-------------|
| python | `CVE-2020-14343-pyyaml`, `CVE-2022-29217-pyjwt`, `CVE-2023-50447-pillow` |
| java | `CVE-2021-44228-log4j`, `CVE-2019-12384-jackson`, `CVE-2022-22965-spring` |
| npm | `CVE-2021-23337-lodash`, `CVE-2022-23812-node-ipc`, `CVE-2021-23358-underscore` |
| go | `CVE-2022-28948-yaml`, `CVE-2021-38561-xtext`, `CVE-2020-28483-gin` |

## Notes

- Apps are **fixtures for static / CPG assessment**, not exploit kits.
- Prefer copying a case's `blueprint.json` into `blueprints/` (or pointing
  `BLUEPRINT_STORE_PATH` at a case directory) when running the pipeline.
- For npm `CVE-2022-23812-node-ipc`, treat as an **inclusion** case (empty sinks);
  do not install/run known-malicious versions on shared hosts.
- Java/Go apps include manifests (`pom.xml` / `go.mod`) so Joern and SCA tools
  can resolve the vulnerable component; compile only if you need a live server.

## Regenerate

```bash
python samples/_generate.py
```
""",
    )


def main() -> None:
    python_samples()
    java_samples()
    npm_samples()
    go_samples()
    write_root_readme()
    print("Wrote samples under", ROOT)


if __name__ == "__main__":
    main()
