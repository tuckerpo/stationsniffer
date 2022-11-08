# Introduction

Thanks for considering making a contribution to this project! Whether it's a code change or a bug report, everything helps!

[[_TOC_]]

## How can I contribute?

### Reporting Bugs

This section guides you through reporting a bug against StationSniffer.
Follow these guidelines to help developers understand your bug report, reproduce the observed behavior, and find related bug reports.

#### Before Submitting a Bug Report

First, check the project's [Jira](https://prplfoundationcloud.atlassian.net/jira/software/c/projects/PPM/issues/) bug list to see if the bug you want to report is already being tracked.

#### Submitting a Good Bug Report

Either contact the developers directly (see `#contact` in the `README.md`) or [file a bug report on the project's Jira page](https://prplfoundationcloud.atlassian.net/jira/software/c/projects/PPM/issues/)

Be sure to include as much detail as you can. A list of things to consider including: 

- build tools and versions used to build the project (if you built it from source), OR a link to where you found a pre-compiled binary.
- An MD5 checksum of the binary
- A thorough description of the behavior you're reporting
- Workarounds you tried that either helped or hurt
- Backtraces or log files where applicable

#### An example 'good' bug report

```
BUG: radiotap_parse.cpp: unaligned access leads to garbage data.
    - Doing a 16 bit unaligned read in the middle of the radiotap buffer causes the channel number information to be read and reported incorrectly
    We should see channel 1 (2.4GHz) but instead we see channel 2314 (32184821 GHz) -- garbage data.
    Built from: <source tree link> using <tools> [<versions>]
```

### The Merge Request Process

All work should be done on feature branches and rebased onto the master branch often. In order to increase transparency and avoid redundant work, developers are encouraged to submit a 'Draft' merge request, which shows everyone what work is being done and allows for real-time feedback while development is happening.

When implementing a new feature or a bugfix, make commits early and often. When your work is finalized and ready to be reviewed, please rebase and clean up your commits so they are atomic and easy to digest.

Each commit should do precisely what it's commit message says, and nothing else. Avoiding side-effects makes the review process much easier for everyone and keeps the project's git history clean. This allows reproducible builds of past commit hashes and makes bugfixing easier when developers want to track down the commit that introduced an issue in the code.

When submitting a merge request, proof of your change working (past unit tests) is appreciated. This can be a screenshot, an inline mp4 on Gitlab, a YouTube link, a live demo, etc...

#### Commit Messages

Commit messages should lead with the general synopsis of what the commit as a whole does, followed by a new line, followed by more detail. All lines should be wrapped at 80 characters.

The title line should be prefixed with the files changes, then the class/struct/method/function

All commits should be signed by developers (i.e. `git commit -s`) -- bonus points for signing with a known GPG key.

There is no length limit for commit messages, but brevity is appreciated.

Example good commit message:
```
main.cpp: threads: join all threads as the main program exits

There was a dangling thread that was not caught by SIGTERM or SIGINT.
Now, we join on all threads and finish gracefully.

Signed-off-by: Tucker Polomik <t.polomik@cablelabs.com>
```

#### Coding Guidelines

This project is written in C++ (C++17) with tidbits of C mixed in. Please prefer C++ wherever possible, especially if it abstracts away machine specific APIs (for example, using `std::thread` instead of `pthread` or `CreateThread(...)`)

Past that, please format your code using `clang-format`, pointed at the `.clang-format` file in the base of the source tree.

Do not introduce "format" commits - just make formatting the last thing you do before a commit, but rarely as it's _own_ commit.

#### Performance Improvement MRs

Sometimes, you may find an area of the code that is poorly optimized for runtime performance. Whether it be a poorly written algorithm, bad data structure choices, or traversing a 2D matrix in column-major order instead of row-major. 

Any performance improvements are appreciated, but it must not come at the sacrifice of readability. We could trim this code down to just inline assembly, and maybe it would be an order of magnitude faster, but it would also become unmaintainable.

Additionally, please provide tangible performance metrics (before & after) for optimization MRs.
