"use strict";

function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function _toConsumableArray(r) { return _arrayWithoutHoles(r) || _iterableToArray(r) || _unsupportedIterableToArray(r) || _nonIterableSpread(); }
function _nonIterableSpread() { throw new TypeError("Invalid attempt to spread non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); }
function _iterableToArray(r) { if ("undefined" != typeof Symbol && null != r[Symbol.iterator] || null != r["@@iterator"]) return Array.from(r); }
function _arrayWithoutHoles(r) { if (Array.isArray(r)) return _arrayLikeToArray(r); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
function _slicedToArray(r, e) { return _arrayWithHoles(r) || _iterableToArrayLimit(r, e) || _unsupportedIterableToArray(r, e) || _nonIterableRest(); }
function _nonIterableRest() { throw new TypeError("Invalid attempt to destructure non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); }
function _iterableToArrayLimit(r, l) { var t = null == r ? null : "undefined" != typeof Symbol && r[Symbol.iterator] || r["@@iterator"]; if (null != t) { var e, n, i, u, a = [], f = !0, o = !1; try { if (i = (t = t.call(r)).next, 0 === l) { if (Object(t) !== t) return; f = !1; } else for (; !(f = (e = i.call(t)).done) && (a.push(e.value), a.length !== l); f = !0); } catch (r) { o = !0, n = r; } finally { try { if (!f && null != t["return"] && (u = t["return"](), Object(u) !== u)) return; } finally { if (o) throw n; } } return a; } }
function _arrayWithHoles(r) { if (Array.isArray(r)) return r; }
function _createForOfIteratorHelper(r, e) { var t = "undefined" != typeof Symbol && r[Symbol.iterator] || r["@@iterator"]; if (!t) { if (Array.isArray(r) || (t = _unsupportedIterableToArray(r)) || e && r && "number" == typeof r.length) { t && (r = t); var _n = 0, F = function F() {}; return { s: F, n: function n() { return _n >= r.length ? { done: !0 } : { done: !1, value: r[_n++] }; }, e: function e(r) { throw r; }, f: F }; } throw new TypeError("Invalid attempt to iterate non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); } var o, a = !0, u = !1; return { s: function s() { t = t.call(r); }, n: function n() { var r = t.next(); return a = r.done, r; }, e: function e(r) { u = !0, o = r; }, f: function f() { try { a || null == t["return"] || t["return"](); } finally { if (u) throw o; } } }; }
function _unsupportedIterableToArray(r, a) { if (r) { if ("string" == typeof r) return _arrayLikeToArray(r, a); var t = {}.toString.call(r).slice(8, -1); return "Object" === t && r.constructor && (t = r.constructor.name), "Map" === t || "Set" === t ? Array.from(r) : "Arguments" === t || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t) ? _arrayLikeToArray(r, a) : void 0; } }
function _arrayLikeToArray(r, a) { (null == a || a > r.length) && (a = r.length); for (var e = 0, n = Array(a); e < a; e++) n[e] = r[e]; return n; }
// Relationship graph — columnar layout (Accounts | Workstations | Servers | Mobile | Network | Services | Findings | MITRE | Indicators)
// with edges for ownership, lateral-movement, and device→IOC connections.

var _React = React,
  useEffect = _React.useEffect,
  useMemo = _React.useMemo,
  useRef = _React.useRef,
  useState = _React.useState;

// Column layout constants
var HEADER_Y = 70;
var FOOTER_Y = 40;
var MIN_ROW_H = 64;
var NODE_H = 44;
var USER_R = 26;
function classifyDevice(d, deviceId) {
  var t = (d.device_type || "").toLowerCase();
  var h = (d.hostname || "").toLowerCase();
  var did = (deviceId || "").toLowerCase();

  // Server detection: check device_type, hostname, AND device ID key
  // Device IDs like "citadeldc01", "DC01-E01_5825", "DC01-ProtectedFiles" contain server clues
  var serverPatterns = /dc\d|citadel|server|srv|domain.?controller/i;
  if (t.includes("server") || h.includes("server") || /\bsrv\b/.test(h) || /\bdc\b/.test(h) || serverPatterns.test(did) || serverPatterns.test(h)) {
    return "server";
  }
  // Check evidence file paths for server indicators (e.g., DC01, citadel-dc01)
  var efiles = d.evidence_files || [];
  if (efiles.some(function (fp) {
    return serverPatterns.test(fp.toLowerCase());
  })) {
    return "server";
  }
  if (t.includes("mobile") || t.includes("ios") || t.includes("android")) return "mobile";
  if (t.includes("network") || t.includes("pcap")) return "network";
  return "pc";
}
function isInternalIP(ip) {
  if (!ip || typeof ip !== "string") return false;
  var parts = ip.split(".").map(Number);
  if (parts.length !== 4) return false;
  if (parts.some(function (p) {
    return isNaN(p) || p < 0 || p > 255;
  })) return false;
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 127) return true;
  if (parts[0] === 169 && parts[1] === 254) return true;
  return false;
}
function extractHostnameFromDeviceId(devId, dev) {
  // 1. Use the hostname field from device_map if available
  if (dev && dev.hostname && typeof dev.hostname === "string" && dev.hostname.trim()) {
    return dev.hostname.trim().toLowerCase();
  }
  // 2. Try to extract hostname from device_id patterns like "memdump_HOSTNAME"
  var did = (devId || "").toLowerCase();
  var memdumpMatch = did.match(/(?:^memdump_|^memory_|^ram_)(.+)/i);
  if (memdumpMatch) return memdumpMatch[1].toLowerCase();
  // 3. Try disk image patterns: "20200918_0347_CDrive" → fall through to devId
  var prefixMatch = did.match(/^\d{8}_\d{4}_/);
  if (prefixMatch) {
    var remainder = did.slice(prefixMatch[0].length);
    if (remainder && remainder !== "cdrive" && remainder !== "c_drive") {
      return remainder.toLowerCase();
    }
  }
  // 4. Fall back to the device_id itself
  return did;
}
function countFlags(flags) {
  var out = {
    total: 0,
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0
  };
  var _iterator = _createForOfIteratorHelper(flags || []),
    _step;
  try {
    for (_iterator.s(); !(_step = _iterator.n()).done;) {
      var f = _step.value;
      out.total++;
      if (out[f.severity] != null) out[f.severity]++;
    }
  } catch (err) {
    _iterator.e(err);
  } finally {
    _iterator.f();
  }
  return out;
}
function maxSev(counts) {
  if (counts.CRITICAL) return "CRITICAL";
  if (counts.HIGH) return "HIGH";
  if (counts.MEDIUM) return "MEDIUM";
  if (counts.LOW) return "LOW";
  return null;
}
function formatEvidenceType(t) {
  if (!t) return "Evidence";
  return t.replace(/_/g, " ").replace(/\b\w/g, function (c) {
    return c.toUpperCase();
  });
}
function guessEvidenceTypeFromPath(p) {
  var fname = (p || "").split("/").pop().toLowerCase();
  var ext = fname.includes(".") ? fname.split(".").pop() : "";
  if (["e01", "ex01", "aff", "aff4", "dd", "img", "raw", "vmdk", "vhdx"].includes(ext)) return "disk_images";
  if (ext === "evtx") return "evtx_logs";
  if (["mem", "lime", "vmem", "dmp"].includes(ext)) return "memory_dumps";
  if (["pcap", "pcapng"].includes(ext)) return "pcaps";
  if (ext === "log" || fname.endsWith("syslog") || fname.endsWith("auth.log")) return "syslogs";
  if (ext === "plist") return "plists";
  if (ext === "db" || ext === "sqlite" || fname === "manifest.db") return "databases";
  if (["dat", "reg", "hive"].includes(ext)) return "registry_hives";
  if (fname === "ntuser.dat" || fname === "system" || fname === "software" || fname === "security" || fname === "sam") return "registry_hives";
  if (ext === "ab") return "mobile_backups";
  return null;
}
function classifyExfilService(host) {
  var h = (host || "").toLowerCase();
  if (h.includes("mega.")) return "Mega.nz";
  if (h.includes("gmail") || h.includes("google")) return "Google";
  if (h.includes("onedrive") || h.includes("microsoft")) return "OneDrive";
  if (h.includes("dropbox")) return "Dropbox";
  if (h.includes("aol")) return "AOL";
  if (h.includes("yahoo")) return "Yahoo";
  if (h.includes("protonmail")) return "ProtonMail";
  if (h.includes("sharepoint")) return "SharePoint";
  if (h.includes("icloud")) return "iCloud";
  return null;
}
function extractUsernameFromPath(filePath) {
  if (!filePath) return null;
  // Scan the ENTIRE path for embedded user directories (even within
  // extraction machine paths like /home/sansforensics/cases/extractions/...).
  // Evidence paths look like: .../Protected Files/Users/mortysmith/NTUSER.DAT
  // or .../Users/ricksanchez/Crypto/Keys/...

  // Windows user paths: .../Users/username/ (embedded anywhere in path)
  var winMatch = filePath.match(/[/\\]Users[/\\]([^/\\]+)/i);
  if (winMatch) {
    var u = winMatch[1];
    // Filter common system accounts that are not real users
    if (["All Users", "Default", "Default User", "Public", "Administrator", "Guest"].includes(u)) return null;
    return u;
  }

  // Linux home paths: /home/username/ (use LAST match to avoid analysis machine prefix)
  var linuxMatches = filePath.match(/[/\\]home[/\\]([^/\\]+)/gi);
  if (linuxMatches) {
    var lastMatch = linuxMatches[linuxMatches.length - 1];
    var m = lastMatch.match(/[/\\]home[/\\]([^/\\]+)/i);
    if (m) {
      var _u = m[1];
      if (["sansforensics", "claw", "root", "nobody", "daemon", "ubuntu", "pi", "vagrant"].includes(_u.toLowerCase())) return null;
      return _u;
    }
  }

  // Protected Files pattern: .../Protected Files/Users/username/
  var protMatch = filePath.match(/[/\\]Protected(?:\s+Files)?[/\\]Users[/\\]([^/\\]+)/i);
  if (protMatch) {
    var _u2 = protMatch[1];
    if (["All Users", "Default", "Default User", "Public", "Administrator", "Guest"].includes(_u2)) return null;
    return _u2;
  }
  return null;
}
function buildIocItems(report) {
  var iocs = report.iocs || {};
  var items = [];
  var addIoc = function addIoc(val, subkind) {
    var id = "i:" + val;
    items.push({
      id: id,
      kind: "ioc",
      subkind: subkind,
      raw: val,
      key: val
    });
  };
  (iocs.ip_addresses || []).slice(0, 6).forEach(function (v) {
    return addIoc(v, "ip");
  });
  (iocs.urls || []).slice(0, 5).forEach(function (v) {
    return addIoc(v, "url");
  });
  (iocs.email_addresses || []).slice(0, 4).forEach(function (v) {
    return addIoc(v, "email");
  });
  return items;
}

// Build findings nodes from behavioral flags and threat indicators
function buildFindingsItems(report) {
  var findings = [];
  var flagsByDevice = report.behavioral_flags || {};
  var seenFindings = new Set();
  Object.entries(flagsByDevice).forEach(function (_ref) {
    var _ref2 = _slicedToArray(_ref, 2),
      devId = _ref2[0],
      flags = _ref2[1];
    (flags || []).forEach(function (flag) {
      // Create node for each unique behavioral flag
      var flagId = "f:" + flag.flag_type + ":" + devId;
      if (!seenFindings.has(flagId)) {
        seenFindings.add(flagId);
        findings.push({
          id: flagId,
          kind: "finding",
          subkind: flag.flag_type || "behavioral",
          flagType: flag.flag_type,
          severity: flag.severity,
          summary: flag.summary,
          deviceId: devId,
          evidence: flag.evidence
        });
      }

      // Extract MITRE ATT&CK techniques if present
      if (flag.mitre_techniques) {
        (flag.mitre_techniques || []).forEach(function (tech) {
          var techId = "m:" + tech.id;
          if (!seenFindings.has(techId)) {
            seenFindings.add(techId);
            findings.push({
              id: techId,
              kind: "mitre",
              subkind: "mitre",
              techniqueId: tech.id,
              name: tech.name || tech.id,
              severity: flag.severity
            });
          }
        });
      }

      // Extract IOCs from flag evidence (with limits to avoid graph clutter)
      var evidence = flag.evidence || {};
      var iocCounts = {
        ip: 0,
        domain: 0,
        hash: 0,
        file_path: 0
      };
      // Count existing IOCs by type
      findings.forEach(function (f) {
        if (f.kind === "ioc") iocCounts[f.subkind] = (iocCounts[f.subkind] || 0) + 1;
      });
      if (evidence.dst_ip && iocCounts.ip < 50) {
        var iocId = "i:" + evidence.dst_ip;
        if (!seenFindings.has(iocId)) {
          seenFindings.add(iocId);
          findings.push({
            id: iocId,
            kind: "ioc",
            subkind: "ip",
            raw: evidence.dst_ip,
            key: evidence.dst_ip
          });
        }
      }
      if (evidence.dst_host && iocCounts.domain < 50) {
        var _iocId = "i:" + evidence.dst_host;
        if (!seenFindings.has(_iocId)) {
          seenFindings.add(_iocId);
          findings.push({
            id: _iocId,
            kind: "ioc",
            subkind: "domain",
            raw: evidence.dst_host,
            key: evidence.dst_host
          });
        }
      }
      if (evidence.hash && iocCounts.hash < 50) {
        var _iocId2 = "i:" + evidence.hash;
        if (!seenFindings.has(_iocId2)) {
          seenFindings.add(_iocId2);
          findings.push({
            id: _iocId2,
            kind: "ioc",
            subkind: "hash",
            raw: evidence.hash,
            key: evidence.hash
          });
        }
      }
      if (evidence.file_path && iocCounts.file_path < 30) {
        // Skip analysis machine paths
        if (!evidence.file_path.startsWith("/home/sansforensics/") && !evidence.file_path.startsWith("/home/claw/") && !evidence.file_path.startsWith("/mnt/") && !evidence.file_path.startsWith("/tmp/")) {
          var _iocId3 = "i:" + evidence.file_path;
          if (!seenFindings.has(_iocId3)) {
            seenFindings.add(_iocId3);
            findings.push({
              id: _iocId3,
              kind: "ioc",
              subkind: "file_path",
              raw: evidence.file_path,
              key: evidence.file_path
            });
          }
        }
      }
    });
  });
  return findings;
}
function aggregateUserFlags(report, username) {
  var user = (report.user_map || {})[username];
  if (!user) return {
    total: 0,
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0
  };
  var agg = {
    total: 0,
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0
  };
  var _iterator2 = _createForOfIteratorHelper(user.devices || []),
    _step2;
  try {
    for (_iterator2.s(); !(_step2 = _iterator2.n()).done;) {
      var devId = _step2.value;
      var c = countFlags((report.behavioral_flags || {})[devId] || []);
      agg.total += c.total;
      agg.CRITICAL += c.CRITICAL;
      agg.HIGH += c.HIGH;
      agg.MEDIUM += c.MEDIUM;
      agg.LOW += c.LOW;
    }
  } catch (err) {
    _iterator2.e(err);
  } finally {
    _iterator2.f();
  }
  return agg;
}
function osLabel(d) {
  // Collect ALL OS indicators from device_type and os_type fields
  var indicators = [];
  var t = (d.device_type || "").toLowerCase();
  var os_t = (d.os_type || "").toLowerCase();
  var os_v = d.os_version || "";
  if (t.includes("ios")) indicators.push("iOS " + os_v);
  if (t.includes("android")) indicators.push("Android " + os_v);
  if (t.includes("mobile")) indicators.push("Mobile/Portable");
  if (os_t === "windows") indicators.push("Windows " + os_v);
  if (os_t === "linux") indicators.push("Linux " + os_v);
  if (os_t === "macos") indicators.push("macOS " + os_v);
  if (t.includes("server") || os_t.includes("server")) indicators.push("Server");
  if (t.includes("network") || t.includes("pcap") || os_t.includes("network")) indicators.push("Network");
  if (indicators.length === 0 && os_t && os_t !== "unknown") indicators.push(os_t.charAt(0).toUpperCase() + os_t.slice(1));
  return indicators.length > 0 ? indicators.join(", ") : d.os_type || "device";
}
function truncate(s, n) {
  s = s == null ? "" : String(s);
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}
function describeNode(n, report) {
  var lines = [];
  if (n.kind === "user") {
    var u = (report.user_map || {})[n.key] || {};
    lines.push("Account: ".concat(u.display_name || n.key));
    if (u.role) lines.push("Role: ".concat(u.role));
    if ((u.aliases || []).length) lines.push("Aliases: ".concat(u.aliases.join(", ")));
    if (n.badge) lines.push("Findings: ".concat(n.badge.count).concat(n.badge.sev ? " (max ".concat(n.badge.sev, ")") : ""));
  } else if (n.kind === "finding") {
    lines.push("Finding: ".concat(n.flagType || n.subkind));
    lines.push("Severity: ".concat(n.severity || "N/A"));
    if (n.summary) lines.push("Summary: ".concat(n.summary));
  } else if (n.kind === "mitre") {
    lines.push("MITRE ATT&CK: ".concat(n.techniqueId));
    if (n.name) lines.push("Name: ".concat(n.name));
  } else if (n.kind === "service") {
    lines.push("Service: ".concat(n.name || "External"));
    if (n.hosts) lines.push("Hosts: ".concat(n.hosts.length));
  } else if (n.kind === "ioc" || n.kind === "external" || n.kind === "network_ip") {
    var label = n.kind === "network_ip" ? "Internal IP" : n.kind === "external" ? "External IP" : "IOC";
    lines.push("".concat(label, ": ").concat(n.subkind.toUpperCase()));
    lines.push("Value: ".concat(n.raw));
  } else {
    // Use consolidated device data if available, otherwise device_map
    var d = n.raw && n.raw.evidence_files ? n.raw : (report.device_map || {})[n.key] || {};
    lines.push("Device: ".concat(d.hostname || n.key));
    lines.push("OS: ".concat(osLabel(d)));
    if (n.originalDeviceIds && n.originalDeviceIds.length > 1) {
      lines.push("Evidence files: ".concat(n.originalDeviceIds.length));
    }
    if (d.owner) lines.push("Owner: ".concat(d.owner));else if (d.metadata && d.metadata.user_profiles_found && d.metadata.user_profiles_found.length > 0) {
      lines.push("Users: ".concat(d.metadata.user_profiles_found.join(", ")));
    }
    if (n.badge) lines.push("Findings: ".concat(n.badge.count).concat(n.badge.sev ? " (max ".concat(n.badge.sev, ")") : ""));
  }
  return lines.join("\n");
}
function describeEdge(e, n1, n2) {
  var a = n1.label || n1.key;
  var b = n2.label || n2.key;
  switch (e.kind) {
    case "owns":
      return "".concat(a, " owns ").concat(b);
    case "seen_on":
      return "".concat(a, " seen on ").concat(b, " (not owner)");
    case "lateral":
      return "Lateral movement: ".concat(a, " \u2192 ").concat(b).concat(e.method ? "\nMethod: ".concat(e.method) : "").concat(e.via ? "\nUser: ".concat(e.via) : "");
    case "exfiltrated_to":
      {
        var parts = ["Exfil/C2: ".concat(a, " \u2192 ").concat(b)];
        if (e.host) parts.push("Host: ".concat(e.host));
        if (e.bytes) parts.push("Bytes: ".concat(e.bytes.toLocaleString()));
        if (e.flag) parts.push("Flag: ".concat(e.flag));
        return parts.join("\n");
      }
    case "has_finding":
      return "Finding on ".concat(b, ": ").concat(e.flagType);
    case "mitre_technique":
      return "".concat(b, " uses technique ").concat(e.techniqueId);
    case "ioc":
      return "".concat(a, " contains IOC ").concat(b);
    default:
      return "".concat(a, " \u2194 ").concat(b);
  }
}
function edgePath(a, b) {
  var isCircular = function isCircular(n) {
    return n.kind === "user" || n.kind === "ioc" || n.kind === "finding" || n.kind === "mitre" || n.kind === "external" || n.kind === "network_ip";
  };
  var _ref3 = a.x < b.x ? [a, b] : [b, a],
    _ref4 = _slicedToArray(_ref3, 2),
    from = _ref4[0],
    to = _ref4[1];
  var sx = from.x + (isCircular(from) ? from.r : from.w / 2);
  var ex = to.x - (isCircular(to) ? to.r : to.w / 2);
  var sy = from.y,
    ey = to.y;
  var mx = (sx + ex) / 2;
  return "M ".concat(sx, " ").concat(sy, " C ").concat(mx, " ").concat(sy, ", ").concat(mx, " ").concat(ey, ", ").concat(ex, " ").concat(ey);
}
function buildGraph(report, size) {
  var userMap = report.user_map || {};
  var deviceMap = report.device_map || {};
  var flagsByDevice = report.behavioral_flags || {};

  // ----------------------------------------------------------------
  // 1. Consolidate devices by hostname (multiple evidence files → one node)
  // ----------------------------------------------------------------
  var deviceIdToConsolidated = {}; // original device_id → consolidated node key
  var consolidatedByHost = {}; // hostname → merged device info
  var consolidatedDevIds = []; // ordered list of consolidated device IDs

  Object.entries(deviceMap).forEach(function (_ref5) {
    var _ref6 = _slicedToArray(_ref5, 2),
      devId = _ref6[0],
      dev = _ref6[1];
    var host = extractHostnameFromDeviceId(devId, dev);
    if (!consolidatedByHost[host]) {
      consolidatedByHost[host] = {
        hostname: host,
        originalDeviceIds: [],
        evidence_files: [],
        evidence_types: [],
        device_type: "unknown",
        os_type: "unknown",
        os_version: "",
        owner: null,
        owner_confidence: "NONE",
        metadata: {},
        discovery_method: "consolidated"
      };
      consolidatedDevIds.push(host);
    }
    deviceIdToConsolidated[devId] = host;
    var cd = consolidatedByHost[host];
    cd.originalDeviceIds.push(devId);
    // Merge evidence files (dedup)
    (dev.evidence_files || []).forEach(function (f) {
      if (!cd.evidence_files.includes(f)) cd.evidence_files.push(f);
    });
    // Merge evidence types (dedup)
    (dev.evidence_types || []).forEach(function (t) {
      if (!cd.evidence_types.includes(t)) cd.evidence_types.push(t);
    });
    // Use the best device_type (prefer non-unknown)
    if (dev.device_type && dev.device_type !== "unknown") {
      if (cd.device_type === "unknown" || dev.device_type !== cd.device_type) {
        cd.device_type = dev.device_type;
      }
    }
    // Use the best os_type
    if (dev.os_type && dev.os_type !== "unknown") {
      cd.os_type = dev.os_type;
      if (dev.os_version) cd.os_version = dev.os_version;
    }
    // Use first real hostname for display
    if (!cd.hostname && dev.hostname && dev.hostname !== host) {
      cd.hostname = dev.hostname;
    }
    // Take first non-null owner
    if (!cd.owner && dev.owner) {
      cd.owner = dev.owner;
      cd.owner_confidence = dev.owner_confidence || "NONE";
    }
    // Merge metadata
    if (dev.metadata) {
      Object.keys(dev.metadata).forEach(function (k) {
        if (!cd.metadata[k]) cd.metadata[k] = dev.metadata[k];
      });
    }
  });

  // Helper: resolve a device reference (original devId or consolidated host) to node ID
  var resolveDeviceNodeId = function resolveDeviceNodeId(devRef) {
    // devRef could be an original device_id OR a consolidated hostname
    if (nodeById["d:" + devRef]) return "d:" + devRef;
    var cons = deviceIdToConsolidated[devRef];
    if (cons && nodeById["d:" + cons]) return "d:" + cons;
    return null;
  };

  // Helper: aggregate flag counts across all original devices in a consolidated device
  var aggregateConsolidatedFlags = function aggregateConsolidatedFlags(host) {
    var cd = consolidatedByHost[host];
    if (!cd) return {
      total: 0,
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0
    };
    var agg = {
      total: 0,
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0
    };
    var _iterator3 = _createForOfIteratorHelper(cd.originalDeviceIds),
      _step3;
    try {
      for (_iterator3.s(); !(_step3 = _iterator3.n()).done;) {
        var did = _step3.value;
        var c = countFlags(flagsByDevice[did] || []);
        agg.total += c.total;
        agg.CRITICAL += c.CRITICAL;
        agg.HIGH += c.HIGH;
        agg.MEDIUM += c.MEDIUM;
        agg.LOW += c.LOW;
      }
    } catch (err) {
      _iterator3.e(err);
    } finally {
      _iterator3.f();
    }
    return agg;
  };

  // ----------------------------------------------------------------
  // 2. Build user list
  // ----------------------------------------------------------------
  var users = Object.entries(userMap).map(function (_ref7) {
    var _ref8 = _slicedToArray(_ref7, 2),
      k = _ref8[0],
      u = _ref8[1];
    return {
      id: "u:" + k,
      kind: "user",
      raw: u || {},
      key: k
    };
  });

  // Extract additional users from device evidence file paths
  var extractedUsernames = new Set();
  Object.entries(deviceMap).forEach(function (_ref9) {
    var _ref0 = _slicedToArray(_ref9, 2),
      devId = _ref0[0],
      dev = _ref0[1];
    var files = dev && dev.evidence_files || [];
    files.forEach(function (fp) {
      var username = extractUsernameFromPath(fp);
      if (username && !userMap[username] && !extractedUsernames.has(username)) {
        extractedUsernames.add(username);
        users.push({
          id: "u:" + username,
          kind: "user",
          raw: {
            username: username,
            display_name: username,
            devices: [devId]
          },
          key: username
        });
      }
    });
  });

  // ----------------------------------------------------------------
  // 3. Build consolidated device items
  // ----------------------------------------------------------------
  var devs = consolidatedDevIds.map(function (host) {
    var cd = consolidatedByHost[host];
    // Use the first original device ID as the key for classification
    var firstDevId = cd.originalDeviceIds[0];
    var devDummy = {
      device_type: cd.device_type,
      os_type: cd.os_type,
      os_version: cd.os_version,
      hostname: cd.hostname,
      evidence_files: cd.evidence_files,
      owner: cd.owner,
      metadata: cd.metadata
    };
    var kind = classifyDevice(devDummy, firstDevId);
    return {
      id: "d:" + host,
      kind: kind,
      raw: cd,
      key: host,
      consolidated: true,
      originalDeviceIds: cd.originalDeviceIds
    };
  });

  // ----------------------------------------------------------------
  // 4. Extract external IPs for a new "External IPs" column
  // ----------------------------------------------------------------
  var externalIPsMap = new Map();
  // Source A: report.iocs.ip_addresses (backend already filters to public IPs)
  var iocIPs = (report.iocs || {}).ip_addresses || [];
  iocIPs.forEach(function (ip) {
    if (!externalIPsMap.has(ip)) {
      externalIPsMap.set(ip, {
        id: "ext:" + ip,
        kind: "external",
        subkind: "ip",
        raw: ip,
        key: ip,
        deviceIds: new Set()
      });
    }
  });
  // Source B: behavioral flag evidence dst_ip fields (external only)
  Object.entries(flagsByDevice).forEach(function (_ref1) {
    var _ref10 = _slicedToArray(_ref1, 2),
      devId = _ref10[0],
      flags = _ref10[1];
    (flags || []).forEach(function (flag) {
      var ev = flag.evidence || {};
      [ev.dst_ip, ev.src_ip].forEach(function (ip) {
        if (ip && typeof ip === "string" && !isInternalIP(ip)) {
          if (!externalIPsMap.has(ip)) {
            externalIPsMap.set(ip, {
              id: "ext:" + ip,
              kind: "external",
              subkind: "ip",
              raw: ip,
              key: ip,
              deviceIds: new Set()
            });
          }
          externalIPsMap.get(ip).deviceIds.add(devId);
        }
      });
    });
  });
  // After collecting all external IPs, backfill device connections for IOC-listed
  // IPs that weren't caught by the behavioral-flag scan (Source B). Scan ALL
  // dst_ip / src_ip fields across every device's behavioral flags and link any
  // that match an already-registered external IP.
  Object.entries(flagsByDevice).forEach(function (_ref11) {
    var _ref12 = _slicedToArray(_ref11, 2),
      devId = _ref12[0],
      flags = _ref12[1];
    (flags || []).forEach(function (flag) {
      var ev = flag.evidence || {};
      [ev.dst_ip, ev.src_ip].forEach(function (ip) {
        if (ip && typeof ip === "string" && externalIPsMap.has(ip)) {
          externalIPsMap.get(ip).deviceIds.add(devId);
        }
      });
    });
  });
  var externalIPItems = Array.from(externalIPsMap.values()).sort(function (a, b) {
    return a.raw.localeCompare(b.raw);
  }).slice(0, 40) // Cap to avoid overwhelming the graph
  .map(function (eip) {
    return _objectSpread(_objectSpread({}, eip), {}, {
      deviceIds: Array.from(eip.deviceIds)
    });
  });

  // ----------------------------------------------------------------
  // 5. Extract internal IPs for the Network column (from PCAP-associated behavioral flags)
  // ----------------------------------------------------------------
  var networkInternalIPs = new Map();
  Object.entries(flagsByDevice).forEach(function (_ref13) {
    var _ref14 = _slicedToArray(_ref13, 2),
      devId = _ref14[0],
      flags = _ref14[1];
    var dev = deviceMap[devId];
    if (!dev) return;
    var kind = classifyDevice(dev, devId);
    var isNetwork = kind === "network";
    (flags || []).forEach(function (flag) {
      var ev = flag.evidence || {};
      // For network devices, extract internal IPs; for others, extract dst_ip for enrichment
      var relevantIPs = isNetwork ? [ev.dst_ip, ev.src_ip] : [ev.dst_ip];
      relevantIPs.forEach(function (ip) {
        if (ip && typeof ip === "string" && isInternalIP(ip) && !networkInternalIPs.has(ip)) {
          networkInternalIPs.set(ip, {
            id: "nip:" + ip,
            kind: "network_ip",
            subkind: "ip",
            raw: ip,
            key: ip,
            deviceId: devId
          });
        }
      });
    });
  });
  var networkIPItems = Array.from(networkInternalIPs.values()).sort(function (a, b) {
    return a.raw.localeCompare(b.raw);
  });

  // ----------------------------------------------------------------
  // 6. Build findings, exfiltration services
  // ----------------------------------------------------------------
  var findingsItems = buildFindingsItems(report);
  var exfilServices = new Map();
  Object.entries(flagsByDevice).forEach(function (_ref15) {
    var _ref16 = _slicedToArray(_ref15, 2),
      devId = _ref16[0],
      flags = _ref16[1];
    (flags || []).forEach(function (flag) {
      var ft = (flag.flag_type || "").toLowerCase();
      var isExfil = ft.includes("exfil") || ft.includes("c2") || ft.includes("beacon") || ft.includes("network_traffic");
      if (!isExfil) return;
      var evidence = flag.evidence || {};
      var dstHost = evidence.dst_host || evidence.dst_ip || "";
      if (!dstHost) return;
      var serviceType = classifyExfilService(dstHost) || "External";
      if (!exfilServices.has(serviceType)) {
        exfilServices.set(serviceType, {
          id: "s:" + serviceType,
          kind: "service",
          name: serviceType,
          hosts: []
        });
      }
      exfilServices.get(serviceType).hosts.push({
        host: dstHost,
        devId: devId,
        flag: flag
      });
    });
  });
  (report.findings_detail || []).forEach(function (fd) {
    var ec = fd.evidence_chain || {};
    var indicators = ec.threat_indicators || [];
    indicators.forEach(function (ind) {
      var dstHost = typeof ind === "string" ? ind : ind.host || ind.ip || ind.url || "";
      if (!dstHost || typeof dstHost !== "string") return;
      var serviceType = classifyExfilService(dstHost);
      if (!serviceType) return;
      if (!exfilServices.has(serviceType)) {
        exfilServices.set(serviceType, {
          id: "s:" + serviceType,
          kind: "service",
          name: serviceType,
          hosts: []
        });
      }
      exfilServices.get(serviceType).hosts.push({
        host: dstHost,
        devId: fd.device_id || "unknown",
        flag: null
      });
    });
  });

  // ----------------------------------------------------------------
  // 7. Define columns
  // ----------------------------------------------------------------
  var networkDevs = devs.filter(function (d) {
    return d.kind === "network";
  });
  // Merge PCAP device items with internal IP items in the Network column
  var networkItems = [].concat(_toConsumableArray(networkDevs), _toConsumableArray(networkIPItems));
  var columns = [{
    key: "user",
    label: "Accounts",
    items: users
  }, {
    key: "pc",
    label: "Workstations",
    items: devs.filter(function (d) {
      return d.kind === "pc";
    })
  }, {
    key: "server",
    label: "Servers",
    items: devs.filter(function (d) {
      return d.kind === "server";
    })
  }, {
    key: "mobile",
    label: "Mobile",
    items: devs.filter(function (d) {
      return d.kind === "mobile";
    })
  }, {
    key: "network",
    label: "Network",
    items: networkItems
  }, {
    key: "external",
    label: "External IPs",
    items: externalIPItems
  }, {
    key: "service",
    label: "Services",
    items: Array.from(exfilServices.values())
  }, {
    key: "finding",
    label: "Findings",
    items: findingsItems.filter(function (f) {
      return f.kind === "finding";
    })
  }, {
    key: "mitre",
    label: "MITRE",
    items: findingsItems.filter(function (f) {
      return f.kind === "mitre";
    })
  }, {
    key: "ioc",
    label: "Indicators",
    items: findingsItems.filter(function (f) {
      return f.kind === "ioc";
    })
  }].filter(function (c) {
    return c.items.length > 0;
  }).map(function (c) {
    return _objectSpread(_objectSpread({}, c), {}, {
      count: c.items.length
    });
  });

  // ----------------------------------------------------------------
  // 8. Layout
  // ----------------------------------------------------------------
  var maxItems = Math.max.apply(Math, [1].concat(_toConsumableArray(columns.map(function (c) {
    return c.items.length;
  }))));
  var computedH = HEADER_Y + FOOTER_Y + maxItems * MIN_ROW_H;
  var totalH = Math.max(size.h, computedH);
  var colCount = columns.length;
  var padX = 40;
  var innerW = size.w - padX * 2;
  var colGap = innerW / colCount;
  var nodeW = Math.max(96, Math.min(150, colGap * 0.84));
  var labelChars = Math.max(10, Math.floor(nodeW / 8));
  var accentMap = {
    user: "#10B981",
    pc: "#3B82F6",
    server: "#A78BFA",
    mobile: "#F59E0B",
    network: "#64748B",
    network_ip: "#64748B",
    finding: "#F59E0B",
    mitre: "#EF4444",
    ioc: "#EF4444",
    external: "#EF4444",
    service: "#EC4899",
    ip: "#EF4444",
    url: "#F97316",
    email: "#EC4899",
    domain: "#8B5CF6",
    hash: "#10B981",
    file_path: "#6B7280"
  };
  var nodeById = {};
  var nodes = [];
  columns.forEach(function (col, ci) {
    col.x = padX + colGap * ci + colGap / 2;
    var topY = HEADER_Y;
    var bottomY = totalH - FOOTER_Y;
    var gapY = (bottomY - topY) / Math.max(col.items.length, 1);
    col.items.forEach(function (item, ri) {
      var y = topY + gapY * ri + gapY / 2;
      var kind = item.kind;
      var isIoc = kind === "ioc";
      var isUser = kind === "user";
      var isFinding = kind === "finding";
      var isMitre = kind === "mitre";
      var isExternal = kind === "external";
      var isNetworkIP = kind === "network_ip";
      var flags = isIoc || isExternal || isNetworkIP ? {
        total: 0,
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0
      } : isUser ? aggregateUserFlags(report, item.key) : item.consolidated ? aggregateConsolidatedFlags(item.key) : countFlags(flagsByDevice[item.deviceId] || []);
      var sev = maxSev(flags);
      var label, sublabel;
      if (isIoc) {
        label = truncate(item.raw, 18);
        sublabel = item.subkind.toUpperCase();
      } else if (isExternal || isNetworkIP) {
        label = truncate(item.raw, 18);
        sublabel = isNetworkIP ? "INTERNAL" : "EXTERNAL";
      } else if (isUser) {
        label = truncate(item.raw.display_name || item.raw.username || item.key, 18);
        sublabel = truncate(item.raw.role || "user", 22);
      } else if (isFinding) {
        label = truncate(item.flagType || item.subkind, 18);
        sublabel = truncate(sev || "N/A", 22);
      } else if (isMitre) {
        label = truncate(item.techniqueId, 18);
        sublabel = truncate(item.name || "MITRE", 22);
      } else {
        label = truncate(item.raw.hostname || item.key, 18);
        sublabel = truncate(osLabel(item.raw), 22);
      }
      var accentKey = isIoc || isExternal || isNetworkIP ? item.subkind : kind;
      var nodeR = isIoc || isFinding || isMitre ? 22 : isExternal || isNetworkIP ? 22 : isUser ? USER_R : 28;
      var nodeW2 = isIoc || isFinding || isMitre || isExternal || isNetworkIP ? 44 : nodeW;
      var nodeH2 = isIoc || isFinding || isMitre || isExternal || isNetworkIP ? 44 : NODE_H;
      var node = {
        id: item.id,
        kind: kind,
        subkind: item.subkind,
        key: item.key,
        label: label,
        sublabel: sublabel,
        x: col.x,
        y: y,
        r: nodeR,
        w: nodeW2,
        h: nodeH2,
        accent: accentMap[accentKey] || "#64748B",
        badge: !isIoc && !isFinding && !isMitre && !isExternal && !isNetworkIP && flags.total > 0 ? {
          count: flags.total,
          sev: sev
        } : null,
        raw: item.raw,
        deviceId: item.deviceId,
        flagType: item.flagType,
        severity: item.severity,
        techniqueId: item.techniqueId,
        consolidated: item.consolidated,
        originalDeviceIds: item.originalDeviceIds
      };
      nodes.push(node);
      nodeById[node.id] = node;
    });
  });

  // ----------------------------------------------------------------
  // 9. Build edges
  // ----------------------------------------------------------------
  var edges = [];
  var seenEdge = new Set();
  var addEdge = function addEdge(e) {
    var k = "".concat(e.from, "|").concat(e.to, "|").concat(e.kind);
    if (seenEdge.has(k)) return;
    seenEdge.add(k);
    edges.push(e);
  };

  // 9a. User <-> Device ownership (map original devIds to consolidated)
  for (var _i = 0, _Object$entries = Object.entries(userMap); _i < _Object$entries.length; _i++) {
    var _Object$entries$_i = _slicedToArray(_Object$entries[_i], 2),
      uname = _Object$entries$_i[0],
      u = _Object$entries$_i[1];
    var _iterator4 = _createForOfIteratorHelper(u.devices || []),
      _step4;
    try {
      for (_iterator4.s(); !(_step4 = _iterator4.n()).done;) {
        var devId = _step4.value;
        var consolidatedNodeId = resolveDeviceNodeId(devId);
        if (!consolidatedNodeId) continue;
        if (!nodeById["u:" + uname] || !nodeById[consolidatedNodeId]) continue;
        var dev = deviceMap[devId] || {};
        var isOwner = dev.owner === uname;
        addEdge({
          from: "u:" + uname,
          to: consolidatedNodeId,
          kind: isOwner ? "owns" : "seen_on"
        });
      }
    } catch (err) {
      _iterator4.e(err);
    } finally {
      _iterator4.f();
    }
  }

  // Extracted users from file paths -> devices (consolidated)
  users.filter(function (u) {
    return !userMap[u.key];
  }).forEach(function (u) {
    var devId = (u.raw.devices || [])[0];
    if (!devId) return;
    var consolidatedNodeId = resolveDeviceNodeId(devId);
    if (consolidatedNodeId && nodeById[consolidatedNodeId]) {
      addEdge({
        from: u.id,
        to: consolidatedNodeId,
        kind: "seen_on"
      });
    }
  });

  // 9b. Lateral movement (consolidated)
  for (var _i2 = 0, _Object$entries2 = Object.entries(report.correlated_users || {}); _i2 < _Object$entries2.length; _i2++) {
    var _Object$entries2$_i = _slicedToArray(_Object$entries2[_i2], 2),
      _uname = _Object$entries2$_i[0],
      cu = _Object$entries2$_i[1];
    var _iterator5 = _createForOfIteratorHelper(cu && cu.lateral_movement_indicators || []),
      _step5;
    try {
      for (_iterator5.s(); !(_step5 = _iterator5.n()).done;) {
        var ind = _step5.value;
        var a = resolveDeviceNodeId(ind.from_device);
        var b = resolveDeviceNodeId(ind.to_device);
        if (a && b && nodeById[a] && nodeById[b]) {
          addEdge({
            from: a,
            to: b,
            kind: "lateral",
            via: _uname,
            method: ind.method
          });
        }
      }
    } catch (err) {
      _iterator5.e(err);
    } finally {
      _iterator5.f();
    }
  }
  var latPath = (report.attack_chain || {}).lateral_movement_path || [];
  for (var i = 0; i < latPath.length - 1; i++) {
    var _a = resolveDeviceNodeId(latPath[i]);
    var _b = resolveDeviceNodeId(latPath[i + 1]);
    if (_a && _b && nodeById[_a] && nodeById[_b]) {
      addEdge({
        from: _a,
        to: _b,
        kind: "lateral",
        via: "attack_chain",
        method: "sequential_access"
      });
    }
  }

  // 9c. Exfiltration: device -> service (consolidated)
  Object.entries(flagsByDevice).forEach(function (_ref17) {
    var _ref18 = _slicedToArray(_ref17, 2),
      devId = _ref18[0],
      flags = _ref18[1];
    (flags || []).forEach(function (flag) {
      var ft = (flag.flag_type || "").toLowerCase();
      var isExfil = ft.includes("exfil") || ft.includes("c2") || ft.includes("beacon") || ft.includes("network_traffic");
      if (!isExfil) return;
      var evidence = flag.evidence || {};
      var dstHost = evidence.dst_host || evidence.dst_ip || "";
      if (!dstHost) return;
      var serviceType = classifyExfilService(dstHost) || "External";
      var serviceNodeId = "s:" + serviceType;
      var consolidatedSrc = resolveDeviceNodeId(devId);
      if (consolidatedSrc && nodeById[consolidatedSrc] && nodeById[serviceNodeId]) {
        addEdge({
          from: consolidatedSrc,
          to: serviceNodeId,
          kind: "exfiltrated_to",
          host: dstHost,
          bytes: evidence.bytes_sent,
          flag: flag.summary
        });
      }
    });
  });
  (report.findings_detail || []).forEach(function (fd) {
    var devId = fd.device_id;
    var consolidatedSrc = resolveDeviceNodeId(devId);
    var ec = fd.evidence_chain || {};
    var indicators = ec.threat_indicators || [];
    indicators.forEach(function (ind) {
      var dstHost = typeof ind === "string" ? ind : ind.host || ind.ip || ind.url || "";
      if (!dstHost || typeof dstHost !== "string") return;
      var serviceType = classifyExfilService(dstHost);
      if (!serviceType) return;
      var serviceNodeId = "s:" + serviceType;
      if (consolidatedSrc && nodeById[consolidatedSrc] && nodeById[serviceNodeId]) {
        addEdge({
          from: consolidatedSrc,
          to: serviceNodeId,
          kind: "exfiltrated_to",
          host: dstHost,
          bytes: null,
          flag: ec.analyst_note || "finding_detail"
        });
      }
    });
  });

  // 9d. Findings -> Device edges (consolidated)
  findingsItems.forEach(function (f) {
    if (f.kind === "finding" && f.deviceId) {
      var _consolidatedNodeId = resolveDeviceNodeId(f.deviceId);
      if (_consolidatedNodeId && nodeById[_consolidatedNodeId]) {
        addEdge({
          from: f.id,
          to: _consolidatedNodeId,
          kind: "has_finding",
          flagType: f.flagType
        });
      }
    }
    if (f.kind === "mitre") {
      Object.entries(flagsByDevice).forEach(function (_ref19) {
        var _ref20 = _slicedToArray(_ref19, 2),
          devId = _ref20[0],
          flags = _ref20[1];
        (flags || []).forEach(function (flag) {
          if (flag.mitre_techniques && flag.mitre_techniques.some(function (t) {
            return t.id === f.techniqueId;
          })) {
            var _consolidatedNodeId2 = resolveDeviceNodeId(devId);
            if (_consolidatedNodeId2 && nodeById[_consolidatedNodeId2]) {
              addEdge({
                from: f.id,
                to: _consolidatedNodeId2,
                kind: "mitre_technique",
                techniqueId: f.techniqueId
              });
            }
          }
        });
      });
    }
    if (f.kind === "ioc") {
      Object.entries(flagsByDevice).forEach(function (_ref21) {
        var _ref22 = _slicedToArray(_ref21, 2),
          devId = _ref22[0],
          flags = _ref22[1];
        (flags || []).forEach(function (flag) {
          var evidence = flag.evidence || {};
          var iocMatch = evidence.dst_ip === f.raw || evidence.dst_host === f.raw || evidence.hash === f.raw || evidence.file_path === f.raw;
          if (iocMatch) {
            var _consolidatedNodeId3 = resolveDeviceNodeId(devId);
            if (_consolidatedNodeId3 && nodeById[_consolidatedNodeId3]) {
              addEdge({
                from: _consolidatedNodeId3,
                to: f.id,
                kind: "ioc"
              });
            }
          }
        });
      });
    }
  });

  // 9e. External IP → Device edges
  externalIPItems.forEach(function (eip) {
    eip.deviceIds.forEach(function (devId) {
      var consolidatedNodeId = resolveDeviceNodeId(devId);
      if (consolidatedNodeId && nodeById[consolidatedNodeId]) {
        addEdge({
          from: consolidatedNodeId,
          to: eip.id,
          kind: "ioc"
        });
      }
    });
  });

  // 9f. Network internal IP → Device edges
  networkIPItems.forEach(function (nip) {
    var consolidatedNodeId = resolveDeviceNodeId(nip.deviceId);
    if (consolidatedNodeId && nodeById[consolidatedNodeId]) {
      addEdge({
        from: consolidatedNodeId,
        to: nip.id,
        kind: "ioc"
      });
    }
  });

  // 9g. If no MITRE techniques from behavioral flags, add from attack_chain
  var acMitres = (report.attack_chain || {}).mitre_techniques_observed || [];
  acMitres.forEach(function (tid) {
    var mitreId = "m:" + tid;
    if (!nodeById[mitreId]) {
      var mitreCol = columns.find(function (c) {
        return c.key === "mitre";
      });
      if (mitreCol) {
        mitreCol.items.push({
          id: mitreId,
          kind: "mitre",
          subkind: "mitre",
          techniqueId: tid,
          name: "",
          severity: "MEDIUM"
        });
        var colX = mitreCol.x;
        var numItems = mitreCol.items.length;
        var gapY = (totalH - HEADER_Y - FOOTER_Y) / Math.max(numItems, 1);
        var y = HEADER_Y + gapY * (numItems - 1) + gapY / 2;
        var node = {
          id: mitreId,
          kind: "mitre",
          subkind: "mitre",
          key: tid,
          label: tid,
          sublabel: "MITRE",
          x: colX,
          y: y,
          r: 22,
          w: 44,
          h: 44,
          accent: "#EF4444",
          badge: null,
          raw: {},
          techniqueId: tid
        };
        nodes.push(node);
        nodeById[mitreId] = node;
        // Connect to all consolidated devices
        consolidatedDevIds.forEach(function (host) {
          addEdge({
            from: mitreId,
            to: "d:" + host,
            kind: "mitre_technique",
            techniqueId: tid
          });
        });
      }
    }
  });
  columns.forEach(function (c) {
    return c.count = c.items.length;
  });
  return {
    nodes: nodes,
    edges: edges,
    nodeById: nodeById,
    columns: columns,
    totalH: totalH
  };
}
function RelationshipGraph(_ref23) {
  var report = _ref23.report,
    selected = _ref23.selected,
    onSelect = _ref23.onSelect,
    hoverId = _ref23.hoverId,
    onHover = _ref23.onHover,
    sevFilter = _ref23.sevFilter;
  var wrapRef = useRef(null);
  var _useState = useState({
      w: 900,
      h: 600
    }),
    _useState2 = _slicedToArray(_useState, 2),
    size = _useState2[0],
    setSize = _useState2[1];
  var svgRef = useRef(null);
  useEffect(function () {
    if (!wrapRef.current) return;
    var ro = new ResizeObserver(function (_ref24) {
      var _ref25 = _slicedToArray(_ref24, 1),
        e = _ref25[0];
      var r = e.contentRect;
      setSize({
        w: Math.max(600, r.width),
        h: Math.max(400, r.height)
      });
    });
    ro.observe(wrapRef.current);
    return function () {
      return ro.disconnect();
    };
  }, []);
  var graph = useMemo(function () {
    return buildGraph(report, size);
  }, [report, size]);
  var neighbors = useMemo(function () {
    if (!selected) return null;
    var set = new Set([selected]);
    var _iterator6 = _createForOfIteratorHelper(graph.edges),
      _step6;
    try {
      for (_iterator6.s(); !(_step6 = _iterator6.n()).done;) {
        var e = _step6.value;
        if (e.from === selected) set.add(e.to);
        if (e.to === selected) set.add(e.from);
      }
    } catch (err) {
      _iterator6.e(err);
    } finally {
      _iterator6.f();
    }
    return set;
  }, [selected, graph]);
  var sevMatch = useMemo(function () {
    if (!sevFilter) return null;
    var set = new Set();
    var flagsByDev = report.behavioral_flags || {};
    var deviceMap = report.device_map || {};
    // Map original device_ids to consolidated hostname-based node IDs
    Object.entries(flagsByDev).forEach(function (_ref26) {
      var _ref27 = _slicedToArray(_ref26, 2),
        devId = _ref27[0],
        flags = _ref27[1];
      if ((flags || []).some(function (f) {
        return f.severity === sevFilter;
      })) {
        var dev = deviceMap[devId];
        var host = dev ? extractHostnameFromDeviceId(devId, dev) : devId;
        set.add("d:" + host);
      }
    });
    Object.entries(report.user_map || {}).forEach(function (_ref28) {
      var _ref29 = _slicedToArray(_ref28, 2),
        uname = _ref29[0],
        u = _ref29[1];
      if ((u.devices || []).some(function (d) {
        var dev = deviceMap[d];
        var host = dev ? extractHostnameFromDeviceId(d, dev) : d;
        return set.has("d:" + host);
      })) set.add("u:" + uname);
    });
    return set;
  }, [sevFilter, report]);

  // Initialize D3 zoom after render
  useEffect(function () {
    if (!svgRef.current || !window.d3) return;
    var svg = window.d3.select(svgRef.current);
    var zoom = window.d3.zoom().scaleExtent([0.1, 4]).on("zoom", function (event) {
      svg.selectAll("g.graph-content").attr("transform", event.transform);
    });
    svg.call(zoom);
    // Double-click to reset zoom
    svg.on("dblclick.zoom", function () {
      svg.transition().duration(500).call(zoom.transform, window.d3.zoomIdentity);
    });
  }, [graph]);
  return /*#__PURE__*/React.createElement("div", {
    ref: wrapRef,
    className: "graph-stage"
  }, /*#__PURE__*/React.createElement("svg", {
    ref: svgRef,
    className: "graph-svg",
    width: "100%",
    height: graph.totalH,
    viewBox: "0 0 ".concat(size.w, " ").concat(graph.totalH),
    preserveAspectRatio: "xMidYMin meet"
  }, /*#__PURE__*/React.createElement("g", {
    className: "graph-content"
  }, graph.columns.map(function (col) {
    return /*#__PURE__*/React.createElement("g", {
      key: col.key
    }, /*#__PURE__*/React.createElement("text", {
      className: "col-header",
      x: col.x,
      y: 28,
      textAnchor: "middle"
    }, col.label.toUpperCase(), " \xB7 ", col.count), /*#__PURE__*/React.createElement("line", {
      className: "col-rule",
      x1: col.x,
      y1: 44,
      x2: col.x,
      y2: graph.totalH - 16
    }));
  }), /*#__PURE__*/React.createElement("g", null, graph.edges.map(function (e, i) {
    var n1 = graph.nodeById[e.from];
    var n2 = graph.nodeById[e.to];
    if (!n1 || !n2) return null;
    var d = edgePath(n1, n2);
    var hl = neighbors && neighbors.has(e.from) && neighbors.has(e.to);
    var dim = neighbors && !hl;
    var cls = "edge";
    if (e.kind === "owns") cls += " owns";else if (e.kind === "seen_on") cls += " seen-on";else if (e.kind === "lateral") cls += " lateral";else if (e.kind === "exfiltrated_to") cls += " exfil";else if (e.kind === "has_finding") cls += " finding-link";else if (e.kind === "mitre_technique") cls += " mitre-link";else if (e.kind === "ioc") cls += " ioc";
    if (hl) cls += " highlighted";
    if (dim) cls += " dimmed";
    return /*#__PURE__*/React.createElement("path", {
      key: i,
      className: cls,
      d: d
    }, /*#__PURE__*/React.createElement("title", null, describeEdge(e, n1, n2)));
  })), /*#__PURE__*/React.createElement("g", null, graph.nodes.map(function (n) {
    var isSel = selected === n.id;
    var isHover = hoverId === n.id;
    var inNbhd = neighbors && neighbors.has(n.id);
    var sevDim = sevMatch && (n.kind === "user" || n.kind === "pc" || n.kind === "server" || n.kind === "mobile" || n.kind === "network") && !sevMatch.has(n.id);
    var dim = neighbors && !inNbhd || sevDim;
    var cls = "node node-" + n.kind;
    if (isSel || isHover) cls += " highlighted";
    if (dim) cls += " dimmed";
    return /*#__PURE__*/React.createElement("g", {
      key: n.id,
      className: cls,
      transform: "translate(".concat(n.x, ", ").concat(n.y, ")"),
      onClick: function onClick() {
        return onSelect(n.id);
      },
      onMouseEnter: function onMouseEnter() {
        return onHover(n.id);
      },
      onMouseLeave: function onMouseLeave() {
        return onHover(null);
      },
      style: {
        color: n.accent
      }
    }, /*#__PURE__*/React.createElement("title", null, describeNode(n, report)), n.kind === "user" ? /*#__PURE__*/React.createElement("circle", {
      cx: 0,
      cy: 0,
      r: n.r,
      fill: "rgba(16,185,129,0.08)",
      stroke: n.accent,
      strokeWidth: isSel ? 2 : 1
    }) : n.kind === "ioc" || n.kind === "external" || n.kind === "network_ip" ? /*#__PURE__*/React.createElement("polygon", {
      points: "0,".concat(-n.r, " ").concat(n.r, ",0 0,").concat(n.r, " ").concat(-n.r, ",0"),
      fill: n.kind === "network_ip" ? "rgba(100,116,139,0.06)" : "rgba(239,68,68,0.06)",
      stroke: n.accent,
      strokeWidth: isSel ? 2 : 1
    }) : n.kind === "finding" ? /*#__PURE__*/React.createElement("rect", {
      x: -n.w / 2,
      y: -n.h / 2,
      width: n.w,
      height: n.h,
      rx: 8,
      fill: "rgba(245,158,11,0.15)",
      stroke: n.accent,
      strokeWidth: isSel ? 2 : 1,
      strokeDasharray: "4 2"
    }) : n.kind === "service" ? /*#__PURE__*/React.createElement("rect", {
      x: -n.w / 2,
      y: -n.h / 2,
      width: n.w,
      height: n.h,
      rx: 12,
      fill: "rgba(236,72,153,0.1)",
      stroke: n.accent,
      strokeWidth: isSel ? 2 : 1
    }) : n.kind === "mitre" ? /*#__PURE__*/React.createElement("rect", {
      x: -n.w / 2,
      y: -n.h / 2,
      width: n.w,
      height: n.h,
      rx: 4,
      fill: "rgba(239,68,68,0.15)",
      stroke: n.accent,
      strokeWidth: isSel ? 2 : 1
    }) : /*#__PURE__*/React.createElement("rect", {
      x: -n.w / 2,
      y: -n.h / 2,
      width: n.w,
      height: n.h,
      rx: 6,
      fill: "rgba(30,41,59,0.9)",
      stroke: n.accent,
      strokeWidth: isSel ? 2 : 1
    }), /*#__PURE__*/React.createElement("text", {
      x: 0,
      y: n.kind === "user" || n.kind === "ioc" || n.kind === "external" || n.kind === "network_ip" ? 4 : -3,
      textAnchor: "middle"
    }, n.label), n.sublabel && /*#__PURE__*/React.createElement("text", {
      x: 0,
      y: n.kind === "user" || n.kind === "ioc" || n.kind === "external" || n.kind === "network_ip" ? 18 : 12,
      textAnchor: "middle",
      className: "sublabel"
    }, n.sublabel), n.badge && /*#__PURE__*/React.createElement("g", {
      transform: "translate(".concat(n.kind === "user" ? n.r - 4 : n.w / 2 - 6, ", ").concat(n.kind === "user" ? -n.r + 4 : -n.h / 2 + 6, ")")
    }, /*#__PURE__*/React.createElement("circle", {
      r: 8,
      className: "flag-badge ".concat(n.badge.sev === "CRITICAL" ? "crit" : n.badge.sev === "HIGH" ? "high" : "")
    }), /*#__PURE__*/React.createElement("text", {
      className: "flag-badge-text"
    }, n.badge.count)));
  })))));
}
window.RelationshipGraph = RelationshipGraph;
window.classifyDevice = classifyDevice;
window.isInternalIP = isInternalIP;
window.extractHostnameFromDeviceId = extractHostnameFromDeviceId;
window.countFlags = countFlags;
window.maxSev = maxSev;
window.aggregateUserFlags = aggregateUserFlags;
window.osLabel = osLabel;
window.extractUsernameFromPath = extractUsernameFromPath;
window.buildFindingsItems = buildFindingsItems;
