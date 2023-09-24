# Comics

> Simple file server for comic books

![GitHub Workflow Status (with event)](https://img.shields.io/github/actions/workflow/status/henry40408/comics/.github%2Fworkflows%2Fworkflow.yaml)
![GitHub](https://img.shields.io/github/license/henry40408/comics)
![GitHub tag (latest SemVer pre-release)](https://img.shields.io/github/v/tag/henry40408/comics)

## Overview

This project provides a self-hosted solution to serve comic books.

## Background

While several options exist for self-hosted comic readers like [Calibre](https://github.com/janeczku/calibre-web), [Komga](https://github.com/gotson/komga), and [Tanoshi](https://github.com/faldez/tanoshi), they often come with complications in setup or format restrictions. Comics seeks to offer a straightforward alternative.

## Features

* **Simple Structure**: Comics looks only at the immediate subdirectories of your chosen folder. Each directory is treated as a book, and the files inside as the pages. No nested subfolders will be scanned. This simplicity ensures you have a clear structure for your comics.
* **Basic Authentication**: Safeguard your comics with a simple username-password protection. 

To set up the authentication:

```bash
$ comics hash-password
Password:
Confirmation:
$2a$10$...Ot6
```
Next, configure your environment variables:

```bash
AUTH_USERNAME=john
AUTH_PASSWORD_HASH=$2a$10$...Ot6
```

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

Now, open your web browser and head to http://localhost:8080/ to view your comics.

## Need Help?

For a comprehensive list of commands and options, type:

```bash
./comics -h
```

## License

MIT
