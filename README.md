# caddy-modsecurity ![License](https://img.shields.io/github/license/kitche/caddy-modsecurity) 

**caddy-modsecurity** integrates [ModSecurity](https://www.modsecurity.org/) with [Caddy](https://caddyserver.com/) to provide a robust Web Application Firewall (WAF). Protect your web applications against SQL injection, XSS, and other OWASP Top 10 vulnerabilities while leveraging Caddy’s simplicity and performance.

---

## Features

- Full ModSecurity v3 integration with Caddy v2
- Blocking (`403`) or logging mode for requests
- Easy configuration with Caddyfile or JSON
- Detailed logging for security auditing

---

## Prerequisites

- [Caddy v2.x](https://caddyserver.com/docs/install)  
- [ModSecurity v3](https://github.com/SpiderLabs/ModSecurity)  
- Linux or BSD-based system recommended

---

## Installation



```bash
git clone https://github.com/yourusername/caddy-modsecurity.git
cd caddy-modsecurity
xcaddy build --with github.com/kitche/caddy-modsecurity=/path/to/checkout
```

## Configuration
Example Caddyfile
```bash
example.com {
    route {
        modsecurity {
            rules_file /etc/caddy/modsecurity.conf
            mode blocking
        }

        reverse_proxy localhost:8080
    }
}
```


## Troubleshooting

Caddy fails to start with modsecurity block: Check your rules syntax in modsecurity.conf.

Requests not being blocked: Ensure SecRuleEngine On and mode blocking are set.

Logs not generated: Confirm the log path exists and Caddy has write permissions.



## Contributing

We welcome contributions!

Fork the repository

Create a branch: git checkout -b feature-name

Commit your changes: git commit -m "Add feature"

Push to your branch: git push origin feature-name

Open a Pull Request

