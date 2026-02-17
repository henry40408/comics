# Comics

> Simple file server for comic books

[![Casual Maintenance Intended](https://casuallymaintained.tech/badge.svg)](https://casuallymaintained.tech/)
![GitHub Workflow Status (with event)](https://img.shields.io/github/actions/workflow/status/henry40408/comics/.github%2Fworkflows%2Fci.yaml)
![GitHub](https://img.shields.io/github/license/henry40408/comics)
![GitHub tag (latest SemVer pre-release)](https://img.shields.io/github/v/tag/henry40408/comics)
[![codecov](https://codecov.io/gh/henry40408/comics/graph/badge.svg?token=26VSHOGXLN)](https://codecov.io/gh/henry40408/comics)

## Overview

This project provides a self-hosted solution to serve comic books.

## Background

While several options exist for self-hosted comic readers like [Calibre](https://github.com/janeczku/calibre-web), [Komga](https://github.com/gotson/komga), and [Tanoshi](https://github.com/faldez/tanoshi), they often come with complications in setup or format restrictions. Comics seeks to offer a straightforward alternative.

## Features

- **Simple Structure**: Comics looks only at the immediate subdirectories of your chosen folder. Each directory is treated as a book, and the files inside as the pages. No nested subfolders will be scanned. This simplicity ensures you have a clear structure for your comics.
- **Basic Authentication**: Safeguard your comics with a simple username-password protection. See [Commands](#commands) and [Environment Variables](#environment-variables) for setup.

## Environment Variables

| Variable | Description | Default |
| --- | --- | --- |
| `AUTH_USERNAME` | Username for basic authentication | _(none)_ |
| `AUTH_PASSWORD_HASH` | Hashed password for basic authentication | _(none)_ |
| `BIND` | Bind host & port | `127.0.0.1:3000` |
| `DATA_DIR` | Data directory | `./data` |
| `DEBUG` | Enable debug mode | _(off)_ |
| `LOG_FORMAT` | Log format (`full`, `compact`, `pretty`, `json`) | `full` |
| `NO_COLOR` | Disable color output ([no-color.org](https://no-color.org/)) | _(off)_ |
| `SEED` | Seed to generate hashed IDs | _(random)_ |

## Setup and Usage

1. **Getting Started**:

   - Clone the repository to your local machine.
   - Navigate to the project directory and install any required dependencies (if applicable).

2. **Organize Your Comics**:

Make sure you have your comics structured as shown below:

```
data
├── book1
│   ├── page1.jpg
│   ├── page2.jpg
│   └── page3.jpg
├── book2
│   ├── page1.jpg
│   ├── page2.jpg
│   └── page3.jpg
└── book3
    ├── page1.jpg
    ├── page2.jpg
    └── page3.jpg
```

Each book directory represents an individual comic book, with image files as the pages.

3. **Run the Server**:

Navigate to the project directory in your terminal or command line and enter:

```bash
./comics
```

Now, open your web browser and head to http://localhost:3000/ to view your comics.

## Commands

### `hash-password`

Generate a bcrypt-hashed password for basic authentication:

```bash
$ comics hash-password
Password:
Confirmation:
$2a$10$...Ot6
```

### `list` (alias: `ls`)

List all books and their page counts:

```bash
$ comics list
Book Title 1 (10P)
Book Title 2 (5P)
2 book(s), 15 page(s), scanned in 1.23ms
```

## Need Help?

For a comprehensive list of options, type:

```bash
./comics -h
```

## License

MIT
