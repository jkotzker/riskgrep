# Third-party test cases

`bash_cases.json` contains 73 cases (every case whose name starts with `sensitive-canary`) translated from the shell-parsing tests of sensitive-canary.

- Repository: https://github.com/coo-quack/sensitive-canary
- Commit: `5ca803b1949e4b336c643610325474d2e5c6ae01`
- Source file: `src/__tests__/pre-tool-use-hook-shell-parsing.test.ts`
- Licence: MIT (full text below)

Each upstream test writes a fixture file and asserts whether a hook blocks the command. Here the command is kept, the fixture's absolute path is replaced by its file name relative to the working directory, and the assertion is restated as the files `bash_targets` must return and whether the result is unresolved. Cases named `sensitive-canary (adapted)` expect a different outcome from upstream because RiskGrep's rules differ: a command's arguments are always checked against the filesystem (so `wc -l file` names `file`), and a shell or interpreter reading its program from a here-document is unresolved rather than parsed. No secret values were copied; every fixture file is created empty at test time.

## Licence

```
MIT License

Copyright (c) 2026 coo-quack

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
