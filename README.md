# pickle-pe

Pickle-pe is a tool for analyzing and extracting information from PE (Portable Executable) files using various parameters.

## Usage

To use `pickle-pe`, execute the following command: pickle-pe.exe <file.exe> -parameter 

![Screenshotpng](https://user-images.githubusercontent.com/10811344/119184504-1ec7fa80-ba7e-11eb-9f43-4d58853c5f48.png)


Parameters:

- `-fi`, `--File Information`: Display information about the PE file.
- `-sh`, `--Section Header`: Display the section headers of the PE file.
- `-ih`, `--Image File Header`: Display the image file header of the PE file.
- `-dh`, `--Dos Header`: Display the DOS header of the PE file.
- `-nt`, `--NT Header`: Display the NT header of the PE file.
- `-oh`, `--Optional Header`: Display the optional header of the PE file.
- `-dd`, `--Data Directory`: Display the data directory of the PE file.
- `-id`, `--Import Directory`: Display the import directory of the PE file.
- `-h`, `--Hex Dump`: Display the hexadecimal dump of the PE file.
- `-s`, `--Strings`: Display the strings embedded in the PE file.

Additional options:

- `--help`: Display the help message.
- `--version`: Display the version information.

## Installation

1. Clone the repository: https://github.com/CaptanMoss/pickle-pe.git
  2. Build the executable using your preferred compiler.

## Example

Here is an example command to display file information:

```bash
pickle-pe.exe sample.exe -fi
```
This command will display information about the sample.exe PE file.

##  Contributing

🤝 Contributions are welcome! If you'd like to contribute to this project, please open a pull request or create an issue to discuss your suggestions.



