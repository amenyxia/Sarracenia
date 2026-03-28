<div align="center">
<img src="icon.svg" width=128 height=128 alt="Logo">
<h1>Sarracenia</h1>

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Go Report Card](https://goreportcard.com/badge/github.com/amenyxia/Sarracenia)](https://goreportcard.com/report/github.com/amenyxia/Sarracenia)
[![Go Version](https://img.shields.io/github/go-mod/go-version/amenyxia/Sarracenia)](https://golang.org)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/amenyxia/Sarracenia)](https://github.com/amenyxia/Sarracenia/releases/latest)
[![Docker Image](https://img.shields.io/badge/ghcr.io-amenyxia/sarracenia-blue?logo=docker)](https://github.com/amenyxia/Sarracenia/pkgs/container/sarracenia)
[![Repo size](https://img.shields.io/github/repo-size/amenyxia/Sarracenia)](https://github.com/amenyxia/Sarracenia)

[![Sarracenia Test / Build / Release](https://github.com/amenyxia/Sarracenia/actions/workflows/go.yml/badge.svg)](https://github.com/amenyxia/Sarracenia/actions/workflows/go.yml)
[![CodeQL](https://github.com/amenyxia/Sarracenia/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/amenyxia/Sarracenia/actions/workflows/github-code-scanning/codeql)

</div>

A high-performance, configurable anti-scraper tarpit server written in Go.

Sarracenia is meant to serve as a defensive countermeasure against web scrapers by serving generated, endless, and 
good-enough web content to be believable. It's primary goal is to trap scrapers and keep them away from your actual 
web content, or as a more strict enforcer for those who don't listen to robots.txt.

Sarracenia is made to use a very low amount of resources while remaining performant, and uses SQLite databases to hold 
data when it's not being used. This allows Sarracenia to have functionality like multiple markov models, each trained 
on hundreds of MB of text data or even larger, while keeping its memory footprint in the double digits at most.

Please note that Sarracenia is currently feature complete, as I have added everything that I wanted to.

If you want new features, or encountered a bug that needs fixing, please open a github issue or a pull request.
Contributions are welcome!

---

### Core Libraries

* **`pkg/markov`**: A persistent Markov chain library supporting streaming generation, database-backed storage, and
  advanced sampling techniques.
    * [Documentation](./pkg/markov/README.md)
* **`pkg/templating`**: A dynamic HTML generation engine capable of producing complex, randomized DOM structures and
  executing logic-heavy templates.
    * [Documentation](./pkg/templating/README.md)

---

## Installation

### 1. From Release (Recommended)

1. Download the latest binary for your OS from
   the [Releases Page](https://github.com/amenyxia/Sarracenia/releases/latest).
2. Download the Source code archive (zip/tar.gz) from the same release.
3. Extract the archive and copy the `example` directory contents to your working folder:
   ```
   /your/app/dir/
   ├── sarracenia              # The binary
   ├── config.json             # From example/config.json
   └── data/                   # From example/data/
   ```
4. Run the binary:
    * Linux/macOS: `./sarracenia`
    * Windows: `.\sarracenia.exe`

### 2. Docker

A pre-built image is available on the GitHub Container Registry.

```yaml
services:
  sarracenia:
    image: ghcr.io/amenyxia/sarracenia:latest
    container_name: sarracenia
    restart: unless-stopped
    ports:
      - "7277:7277" # Tarpit Server
      - "7278:7278" # Dashboard & API
    volumes:
      - ./data:/app/data
```

### 3. From Source

**Prerequisites:** Go 1.24+

```sh
git clone https://github.com/amenyxia/Sarracenia.git
cd Sarracenia
go build -o sarracenia ./cmd/main
./sarracenia
```

---

## Testing

```sh
# Run all tests
go test ./...

# Run a specific package
go test ./pkg/markov/
go test ./cmd/main/

# Run a single test by name
go test ./cmd/main/ -run TestGetClientIP
```

---

## Initial Setup

1. **Access the Dashboard**:
   By default, the dashboard runs on port `:7278`. Open a browser and navigate to `http://localhost:7278`.

2. **Create Master API Key**:
   Upon first launch, the API is unsecured to allow initialization.
    * Navigate to the **API Keys** page.
    * Create a new key. The first key created is automatically assigned the Master (`*`) scope.
    * **Copy this key immediately.** It will not be shown again.
    * Once created, the API and Dashboard are immediately secured, and you will be logged in automatically.

---

## Configuration

Configuration is managed via `config.json`.

### Server Configuration (`server_config`)

| Key                     | Description                                           | Default                                                            |
|:------------------------|:------------------------------------------------------|:-------------------------------------------------------------------|
| `server_addr`           | Tarpit server listener address.                       | `:7277`                                                            |
| `api_addr`              | API/Dashboard server listener address.                | `:7278`                                                            |
| `log_level`             | Logging verbosity (`debug`, `info`, `warn`, `error`). | `info`                                                             |
| `trusted_proxies`       | List of CIDRs or IPs to trust for X-Forwarded-For.    | `[]`                                                               |
| `data_dir`              | Base directory for data files.                        | `./data`                                                           |
| `markov_database_path`  | Path to the Markov chain database.                    | `./data/sarracenia_markov.db?_journal_mode=WAL&_busy_timeout=5000` |
| `auth_database_path`    | Path to the Auth/Whitelist database.                  | `./data/sarracenia_auth.db?_journal_mode=WAL&_busy_timeout=5000`   |
| `stats_database_path`   | Path to the Statistics database.                      | `./data/sarracenia_stats.db?_journal_mode=WAL&_busy_timeout=5000`  |
| `dashboard_tmpl_path`   | Path to dashboard templates.                          | `./data/dashboard/templates/`                                      |
| `dashboard_static_path` | Path to dashboard static assets.                      | `./data/dashboard/static/`                                         |
| `enabled_templates`     | List of templates enabled for random selection.       | `["page.tmpl.html"]`                                               |

### Tarpit Configuration (`tarpit_config`)

Controls the behavior of the tarpit response mechanism.

| Key                         | Description                                                          | Default                                                                                                                                                                                                                                     |
|:----------------------------|:---------------------------------------------------------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `enable_drip_feed`          | If true, responses are sent in slow chunks to hold connections open. | `false`                                                                                                                                                                                                                                     |
| `min_initial_delay_ms`      | Minimum delay before sending the first byte.                         | `0`                                                                                                                                                                                                                                         |
| `max_initial_delay_ms`      | Maximum delay before sending the first byte.                         | `15000`                                                                                                                                                                                                                                     |
| `min_drip_feed_delay_ms`    | Minimum delay between subsequent chunks.                             | `500`                                                                                                                                                                                                                                       |
| `max_drip_feed_delay_ms`    | Maximum delay between subsequent chunks.                             | `1000`                                                                                                                                                                                                                                      |
| `min_drip_feed_chunks`      | Minimum total chunks to split the response into.                     | `1`                                                                                                                                                                                                                                         |
| `max_drip_feed_chunks`      | Maximum total chunks to split the response into.                     | `20`                                                                                                                                                                                                                                        |
| `headers`                   | HTTP headers that the tarpit replies to each request with.           | `{"Cache-Control":"no-store, no-cache","Pragma":"no-cache","Expires":"0","Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';","Content-Type":"text/html; charset=utf-8",}` |

### Statistics Configuration (`stats_config`)

| Key                  | Description                                      | Default |
|:---------------------|:-------------------------------------------------|:--------|
| `sync_interval_sec`  | Frequency of flushing stats from memory to disk. | `30`    |
| `forget_threshold`   | Minimum hits required to retain an IP record.    | `10`    |
| `forget_delay_hours` | Time without activity before a record is pruned. | `24`    |

### Template Configuration (`template_config`)

| Key                          | Description                                                                             | Default         |
|:-----------------------------|:----------------------------------------------------------------------------------------|:----------------|
| `markov_enabled`             | Controls whether `markov` functions use the generator. Falls back to `random` if false. | `true`          |
| `markov_separator`           | Separator used by the markov tokenizer.                                                 | `""`            |
| `markov_eoc`                 | End-of-chain marker used by the markov tokenizer.                                       | `""`            |
| `markov_split_regex`         | Regex for splitting tokens in the markov tokenizer.                                     | `""`            |
| `markov_eoc_regex`           | Regex for detecting EOC tokens.                                                         | `""`            |
| `markov_separator_exc_regex` | Regex for tokens that should not have a separator prefix.                               | `""`            |
| `markov_eoc_exc_regex`       | Regex for tokens that should not have an EOC suffix.                                    | `""`            |
| `path_whitelist`             | URL paths considered safe; excluded from random link generation.                        | `[]`            |
| `min_subpaths`               | Minimum number of segments in generated URL paths.                                      | `1`             |
| `max_subpaths`               | Maximum number of segments in generated URL paths.                                      | `5`             |
| `max_json_depth`             | Hard limit on recursion depth for `randomJSON`.                                         | `8`             |
| `max_nest_divs`              | Hard limit on recursion depth for `nestDivs`.                                           | `50`            |
| `max_table_rows`             | Maximum rows for `randomComplexTable`.                                                  | `100`           |
| `max_table_cols`             | Maximum columns for `randomComplexTable`.                                               | `50`            |
| `max_form_fields`            | Maximum fields for `randomForm`.                                                        | `75`            |
| `max_style_rules`            | Maximum complex CSS rules for `randomStyleBlock`.                                       | `200`           |
| `max_css_vars`               | Maximum interdependent CSS variables for `randomCSSVars`.                               | `100`           |
| `max_svg_elements`           | Complexity limit for `randomSVG`.                                                       | `7`             |
| `max_js_content_size`        | Maximum content size (bytes) for `jsInteractiveContent`.                                | `1048576` (1MB) |
| `max_js_waste_cycles`        | Maximum waste loop iterations for `jsInteractiveContent`.                               | `1,000,000`     |

### Threat Configuration (`threat_config`)

Configures the heuristic threat assessment system.

| Key                  | Description                                     | Default |
|:---------------------|:------------------------------------------------|:--------|
| `base_threat`        | Initial score for any request.                  | `0`     |
| `ip_hit_factor`      | Score added per IP hit.                         | `1.0`   |
| `ua_hit_factor`      | Score added per User Agent hit.                 | `0.5`   |
| `ip_hit_rate_factor` | Multiplier for IP hit rate (hits/min).          | `10.0`  |
| `ua_hit_rate_factor` | Multiplier for UA hit rate (hits/min).          | `5.0`   |
| `max_threat`         | Maximum possible threat score.                  | `1000`  |
| `fallback_level`     | Default threat stage (0-4) if no threshold met. | `0`     |

**Threat Stages:**
Stages define thresholds for triggering increasingly aggressive tarpit templates.

| Stage     | Enabled | Threshold |
|:----------|:--------|:----------|
| `stage_1` | `True`  | `0`       |
| `stage_2` | `False` | `25`      |
| `stage_3` | `False` | `50`      |
| `stage_4` | `False` | `75`      |
| `stage_5` | `False` | `100`     |

---

## API Reference

**Note:** The API is designed for internal use by the dashboard. It does not implement rate limiting. Do not expose the
API port directly to the public internet.

All endpoints require the `sarr-auth` header containing a valid API key.

### Authentication (`/api/auth`)

| Method   | Endpoint              | Scope         | Description                                        |
|:---------|:----------------------|:--------------|:---------------------------------------------------|
| `GET`    | `/api/auth/me`        | *Any*         | Validates current session.                         |
| `GET`    | `/api/auth/keys`      | `auth:manage` | Lists API keys.                                    |
| `POST`   | `/api/auth/keys`      | `auth:manage` | Creates a new key. **First key is always Master.** |
| `DELETE` | `/api/auth/keys/{id}` | `auth:manage` | Deletes a key.                                     |

### Markov Models (`/api/markov`)

**Do note:** Only one model can be trained at a time. Simultaneous training jobs will result in database
lock errors.

| Method   | Endpoint                             | Scope          | Description                       |
|:---------|:-------------------------------------|:---------------|:----------------------------------|
| `GET`    | `/api/markov/models`                 | `markov:read`  | Lists available models.           |
| `POST`   | `/api/markov/models`                 | `markov:write` | Creates a new model.              |
| `DELETE` | `/api/markov/models/{name}`          | `markov:write` | Deletes a model.                  |
| `POST`   | `/api/markov/models/{name}/train`    | `markov:write` | Trains a model (Text/Plain body). |
| `POST`   | `/api/markov/models/{name}/prune`    | `markov:write` | Prunes model data.                |
| `GET`    | `/api/markov/models/{name}/export`   | `markov:read`  | Exports model as JSON.            |
| `POST`   | `/api/markov/models/{name}/generate` | `markov:read`  | Generates text.                   |
| `POST`   | `/api/markov/import`                 | `markov:write` | Imports a model from JSON.        |
| `POST`   | `/api/markov/vocabulary/prune`       | `markov:write` | Global vocabulary pruning.        |
| `GET`    | `/api/markov/training/status`        | `markov:read`  | Checks training status.           |

### Server Control (`/api/server`)

| Method | Endpoint               | Scope            | Description          |
|:-------|:-----------------------|:-----------------|:---------------------|
| `GET`  | `/api/health`          | *None*           | Health check.        |
| `GET`  | `/api/server/version`  | `stats:read`     | Server version info. |
| `GET`  | `/api/server/config`   | `server:config`  | Get current config.  |
| `PUT`  | `/api/server/config`   | `server:config`  | Update config.       |
| `POST` | `/api/server/restart`  | `server:control` | Restart server.      |
| `POST` | `/api/server/shutdown` | `server:control` | Shutdown server.     |

### Statistics (`/api/stats`)

| Method   | Endpoint                     | Scope            | Description               |
|:---------|:-----------------------------|:-----------------|:--------------------------|
| `GET`    | `/api/stats/summary`         | `stats:read`     | Global request summary.   |
| `GET`    | `/api/stats/top_ips`         | `stats:read`     | Top 100 IPs by hit count. |
| `GET`    | `/api/stats/top_user_agents` | `stats:read`     | Top 100 User Agents.      |
| `DELETE` | `/api/stats/all`             | `server:control` | **Reset all statistics.** |

### Templates (`/api/templates`)

| Method   | Endpoint                 | Scope             | Description                 |
|:---------|:-------------------------|:------------------|:----------------------------|
| `GET`    | `/api/templates`         | `templates:read`  | List all templates.         |
| `GET`    | `/api/templates/{name}`  | `templates:read`  | Get template content.       |
| `PUT`    | `/api/templates/{name}`  | `templates:write` | Create/Update template.     |
| `DELETE` | `/api/templates/{name}`  | `templates:write` | Delete template.            |
| `POST`   | `/api/templates/refresh` | `templates:write` | Reload templates from disk. |
| `POST`   | `/api/templates/test`    | `templates:read`  | Test template syntax.       |
| `GET`    | `/api/templates/preview` | `templates:read`  | Render template preview.    |

### Whitelist (`/api/whitelist`)

| Method   | Endpoint                   | Scope             | Description                       |
|:---------|:---------------------------|:------------------|:----------------------------------|
| `GET`    | `/api/whitelist/ip`        | `whitelist:read`  | List whitelisted IPs.             |
| `POST`   | `/api/whitelist/ip`        | `whitelist:write` | Add IP to whitelist.              |
| `DELETE` | `/api/whitelist/ip`        | `whitelist:write` | Remove IP from whitelist.         |
| `GET`    | `/api/whitelist/useragent` | `whitelist:read`  | List whitelisted User Agents.     |
| `POST`   | `/api/whitelist/useragent` | `whitelist:write` | Add User Agent to whitelist.      |
| `DELETE` | `/api/whitelist/useragent` | `whitelist:write` | Remove User Agent from whitelist. |

---



A special thank you to [Nepenthes](https://zadzmo.org/code/nepenthes/) for the inspiration.

This project is *technically* a fork from the initial version of 
[Chunchunmaru](https://github.com/BrandenStoberReal/Chunchunmaru), which I majorly contributed to before the fork there 
was made. This is the reason for the similarities in functions for template generation and other project structure. 
However, I started from scratch and wrote Sarracenia from the ground up to fit my original vision for the project.

Gemini CLI was used to make the dashboard, as I am not an experienced frontend/html programmer, nor do I plan on being 
one. If anyone would like to make their own, improved version, I would be glad to accept it as a replacement.