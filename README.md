# Comics

> Simple file server for comic books

![GitHub Workflow Status (with event)](https://img.shields.io/github/actions/workflow/status/henry40408/comics/.github%2Fworkflows%2Fworkflow.yaml)
![GitHub](https://img.shields.io/github/license/henry40408/comics)
![GitHub tag (latest SemVer pre-release)](https://img.shields.io/github/v/tag/henry40408/comics)

## Background

There are already several options for self-hosted comic readers, such as [Calibre](https://github.com/janeczku/calibre-web), [Komga](https://github.com/gotson/komga), or [Tanoshi](https://github.com/faldez/tanoshi). However, they are either in the early stages of development, too complicated to install and configure, or require comic books to be in specific formats like CBZ, CBR, EPUB, or PDF. Therefore, I have decided to implement my own solution.

## Features

* Simple: The server only searches one layer of the file system. Each directory represents a book, and the files within the directory represent the pages. That's all.
* Basic auth: A dead simple way to protect your comics.

To obtain a hashed password, use the "comics hash-password" command like Caddy.

```
$ comics hash-password
Password:
Confirmation:
$2a$10$...Ot6
```

Then, set the hashed password in environment variables:

```
PASSWORD=$2a$10$...Ot6
```

## Out of scope

* Tests: This project is too simple to require unit tests or integration tests.

## How to use

Assuming you have a directory called "data" with the following structure:

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

The "data" directory contains three subdirectories: "book1", "book2", and "book3". Each book directory represents a separate book, and within each book directory, there are multiple image files representing the pages of that book (e.g., "page1.jpg", "page2.jpg", etc.).

Then run the server:

```
./comics
```

Then open the browser and navigate to http://localhost:8080/.

## Help

```
./comics -h
```

## License

MIT
