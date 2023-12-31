# BlockIt

BlockIt is a Python package that provides various encryption algorithms and a CLI application for easy encryption and decryption of text. It implements the ShiftEncryption, ReverseEncryption, and MatrixEncryption algorithms and allows dynamic selection of encryption algorithms using Abstract Factory design pattern.

## Deliverables

- [x] Implemented the following encryption algorithms: ShiftEncryption, ReverseEncryption, MatrixEncryption
- [x] Add the `--shift` option to specify the number of shifts to be performed instead of being fixed at 3
- [x] Dockerized the project, enabling easy testing of the application in a containerized environment using docker-compose
- [x] Utilized the Abstract Factory Design Pattern, enabling dynamic creation of encryption algorithms
- [x] Developed a CLI application using `Typer`, facilitating easy text encryption and decryption
- [x] Distributed and published the package on PyPI at https://pypi.org/project/blockit/
- [x] Reimplemented the Reverse Encryption Algorithm and deployed it on Vercel as a FastAPI application. This was necessary due to the previously provided endpoints experiencing timeouts and functionality issues.
- [x] Published a Postman collection for the API endpoints, available at https://documenter.getpostman.com/view/8975155/2s93zB528T
- [x] Utilized semantic commit messages to effectively track the project's progress
- [x] Wrote comprehensive unit tests for all encryption algorithms: ShiftEncryption, ReverseEncryption, MatrixEncryption
- [x] Utilized `pytest` and `pytest-cov` to run tests and generate coverage reports
- [x] Incorporated `pre-commit` hooks to ensure consistent formatting, type checking, and linting before each commit
- [x] Automated formatting and versioning of the package using a `Makefile`
- [x] Documentation including installation instructions, usage guidelines, known issues, testing instructions, and research details.

## Installation

### Inside a Docker Container

1. Run `docker-compose up --build` to build the image and run the container
2. Run `docker-compose exec web bash` to enter the container
3. The `blockit` CLI is now available inside the container
4. Or run `python -m blockit` inside the container too

### Published CLI

1. Install the package using `pip install blockit`
2. Run `blockit --help` to see the available commands and options
```bash
                                                                                                                                                                                                 
 Usage: blockit [OPTIONS] TEXT ALGORITHM METHOD                                                                                                                                                  
                                                                                                                                                                                                 
╭─ Arguments ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    text           TEXT  Text to be encrypted/decrypted [default: None] [required]                                                                                                           │
│ *    algorithm      TEXT  Encryption algorithm to be used [default: None] [required]                                                                                                          │
│ *    method         TEXT  Method to be used: 'Encrypt' or 'Decrypt' [default: None] [required]                                                                                                │
╰───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### Manually

1. Clone the repository, `git clone https://github.com/0xsirsaif/blockit`, and `cd` into it
2. Create a virtual environment, `python -m venv venv`, and activate it, `source venv/bin/activate`
3. Install the dependencies, `pip install -r requirements.txt`
4. Run `python -m blockit --help` to see the available commands and options

## Usage

### ShiftEncryption

- default shift value is 3, but can be changed using the `--shift` option

```bash
$ blockit "Hello World" shift Encrypt
Khoor Zruog
```

```bash
$ blockit "Khoor Zruog" shift Decrypt
Hello World
```

### ReverseEncryption

```bash
$ blockit "Hello World" reverse Encrypt
dlroW olleH
```

```bash
$ blockit "dlroW olleH" reverse Decrypt
Hello World
```

### MatrixEncryption

```bash
$ blockit "Hello World" matrix Encrypt
```

```bash
$ blockit "Hello World" matrix Decrypt
```

## Testing

Tests are grouped into three Test Classes: TestShiftEncryption, TestReverseEncryption, and TestMatrixEncryption.

- To run all tests, run the following command:

```bash
$ python -m pytest --cov tests/ -vvs
```

- To run a specific test with keyword, run the following command:

```bash
$ python -m pytest --cov tests/ -vvs -k <keyword>
```

## Known Issues

Please be aware that there is currently a bug in the `MatrixEncryption` algorithm. I have been unable to fix it in time for the deadline, but I will continue working on it and will push the fix as soon as possible. I've added a test case for the bug as well.

## License

MIT License
