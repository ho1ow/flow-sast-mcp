"""
shared/sink_catalog.py
───────────────────────
Single source of truth for KNOWN_SINK_MAPPING used by classify_sink tool.
Includes PHP, Python, Node, Java, Go, Ruby, C# sinks.

Lookup table only — no LLM.
"""

from __future__ import annotations

from typing import Dict

# ── PHP / Framework sinks ──────────────────────────────────────────────────────
KNOWN_SINK_MAPPING: Dict[str, str] = {
    # ── SQLi ──────────────────────────────────────────────────
    "DB::statement":                "sqli",
    "DB::select":                   "sqli",
    "DB::insert":                   "sqli",
    "DB::update":                   "sqli",
    "DB::unprepared":               "sqli",
    "whereRaw":                     "sqli",
    "orderByRaw":                   "sqli",
    "groupByRaw":                   "sqli",
    "selectRaw":                    "sqli",
    "havingRaw":                    "sqli",
    "mysqli_query":                 "sqli",
    "mysqli_real_query":            "sqli",
    "mysql_query":                  "sqli",
    "PDO::exec":                    "sqli",
    "PDO::query":                   "sqli",
    "PDOStatement::execute":        "sqli",
    "pg_query":                     "sqli",
    "pg_execute":                   "sqli",
    # Python
    "cursor.execute":               "sqli",
    "cursor.executemany":           "sqli",
    "engine.execute":               "sqli",
    "session.execute":              "sqli",
    "RawSQL":                       "sqli",
    "extra":                        "sqli",
    "raw":                          "sqli",
    # Node
    "db.query":                     "sqli",
    "pool.query":                   "sqli",
    "connection.query":             "sqli",
    "sequelize.query":              "sqli",
    "knex.raw":                     "sqli",
    "db.raw":                       "sqli",
    # Java
    "createNativeQuery":            "sqli",
    "createQuery":                  "sqli",
    "executeQuery":                 "sqli",
    "executeUpdate":                "sqli",
    # C#
    "SqlCommand":                   "sqli",
    "context.Database.ExecuteSqlRaw": "sqli",
    "FromSqlRaw":                   "sqli",

    # ── RCE ───────────────────────────────────────────────────
    "exec":                         "rce",
    "system":                       "rce",
    "shell_exec":                   "rce",
    "passthru":                     "rce",
    "popen":                        "rce",
    "proc_open":                    "rce",
    "pcntl_exec":                   "rce",
    "os.system":                    "rce",
    "os.popen":                     "rce",
    "subprocess.run":               "rce",
    "subprocess.Popen":             "rce",
    "subprocess.call":              "rce",
    "subprocess.check_output":      "rce",
    "child_process.exec":           "rce",
    "child_process.execSync":       "rce",
    "child_process.spawn":          "rce",
    "eval":                         "rce",
    "Process.Start":                "rce",

    # ── LFI / Path Traversal ──────────────────────────────────
    "include":                      "lfi",
    "require":                      "lfi",
    "include_once":                 "lfi",
    "require_once":                 "lfi",
    "file_get_contents":            "lfi",
    "file_put_contents":            "path_traversal",
    "fwrite":                       "path_traversal",
    "move_uploaded_file":           "path_traversal",
    "unlink":                       "path_traversal",
    "fs.writeFile":                 "path_traversal",
    "fs.writeFileSync":             "path_traversal",
    "open":                         "path_traversal",
    "File.WriteAllText":            "path_traversal",
    "File.ReadAllText":             "path_traversal",
    "Path.Combine":                 "path_traversal",

    # ── XXE ───────────────────────────────────────────────────
    "simplexml_load_string":        "xxe",
    "simplexml_load_file":          "xxe",
    "DOMDocument::loadXML":         "xxe",
    "DOMDocument.loadXML":          "xxe",
    "DOMDocument.load":             "xxe",
    "etree.fromstring":             "xxe",
    "etree.parse":                  "xxe",
    "XmlDocument.LoadXml":          "xxe",
    "XmlDocument.Load":             "xxe",
    "DocumentBuilder.parse":        "xxe",
    "SAXParser.parse":              "xxe",

    # ── Deserialization ───────────────────────────────────────
    "unserialize":                  "deserialize",
    "yaml_parse":                   "deserialize",
    "pickle.loads":                 "deserialize",
    "pickle.load":                  "deserialize",
    "yaml.load":                    "deserialize",
    "marshal.loads":                "deserialize",
    "jsonpickle.decode":            "deserialize",
    "dill.loads":                   "deserialize",
    "ObjectInputStream.readObject": "deserialize",
    "XStream.fromXML":              "deserialize",
    "BinaryFormatter.Deserialize":  "deserialize",
    "JavaScriptSerializer.Deserialize": "deserialize",
    "TypeNameHandling":             "deserialize",

    # ── SSTI ──────────────────────────────────────────────────
    "render_template_string":       "ssti",
    "Environment().from_string":    "ssti",
    "env.from_string":              "ssti",
    "Twig.createTemplate":          "ssti",
    "Markup":                       "ssti",

    # ── XSS ───────────────────────────────────────────────────
    "echo":                         "xss",
    "print":                        "xss",
    "innerHTML":                    "xss",
    "document.write":               "xss",
    "dangerouslySetInnerHTML":      "xss",
    "res.send":                     "xss",
    "Html.Raw":                     "xss",
    "Response.Write":               "xss",

    # ── SSRF ──────────────────────────────────────────────────
    "curl_exec":                    "ssrf",
    "fsockopen":                    "ssrf",
    "requests.get":                 "ssrf",
    "requests.post":                "ssrf",
    "requests.request":             "ssrf",
    "urllib.request.urlopen":       "ssrf",
    "httpx.get":                    "ssrf",
    "httpx.post":                   "ssrf",
    "fetch":                        "ssrf",
    "axios.get":                    "ssrf",
    "axios.post":                   "ssrf",
    "HttpClient.GetAsync":          "ssrf",
    "WebClient.DownloadString":     "ssrf",

    # ── Redirect / CRLF ──────────────────────────────────────
    "header":                       "crlf",
    "header()":                     "crlf",
    "Response.Redirect":            "redirect",
    "redirect":                     "redirect",
    "Redirect::to":                 "redirect",
    "Redirect":                     "redirect",

    # ── Weak Crypto ───────────────────────────────────────────
    "md5":                          "weak_crypto",
    "sha1":                         "weak_crypto",
    "crc32":                        "weak_crypto",

    # ── Authz / Logic ─────────────────────────────────────────
    "Model::find":                  "idor",
    "$request->all":                "mass_assign",
    "fill":                         "mass_assign",
}
