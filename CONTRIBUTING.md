<!--
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
-->

# Contributing to APISIX

Firstly, thanks for your interest in contributing! I hope that this will be a
pleasant first experience for you, and that you will return to continue
contributing.

## How to contribute?

Most of the contributions that we receive are code contributions, but you can
also contribute to the documentation or simply report solid bugs
for us to fix.

 For new contributors, please take a look at issues with a tag called [Good first issue](https://github.com/apache/apisix/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) or [Help wanted](https://github.com/apache/apisix/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22).

## How to report a bug?

* **Ensure the bug was not already reported** by searching on GitHub under [Issues](https://github.com/apache/apisix/issues).

* If you're unable to find an open issue addressing the problem, [open a new one](https://github.com/apache/apisix/issues/new). Be sure to include a **title and clear description**, as much relevant information as possible, and a **code sample** or an **executable test case** demonstrating the expected behavior that is not occurring.

## How to add a new feature or change an existing one

_Before making any significant changes, please [open an issue](https://github.com/apache/apisix/issues)._ Discussing your proposed changes ahead of time will make the contribution process smooth for everyone.

Once we've discussed your changes and you've got your code ready, make sure that tests are passing and open your pull request. Your PR is most likely to be accepted if it:

* Update the README.md with details of changes to the interface.
* Includes tests for new functionality.
* References the original issue in the description, e.g. "Resolves #123".
* Has a [good commit message](http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html).
* Ensure your pull request's title starts from one of the word in the `types` section of [semantic.yml](https://github.com/apache/apisix/blob/master/.github/semantic.yml).
* Follow the [PR manners](https://raw.githubusercontent.com/apache/apisix/master/.github/PULL_REQUEST_TEMPLATE.md)

## Contribution Guidelines for Documentation

* Linting/Style

    For linting both our Markdown and YAML files we use:

    - npm based [markdownlint-cli](https://www.npmjs.com/package/markdownlint-cli)

* Active Voice

    In general, use active voice when formulating the sentence instead of passive voice. A sentence written in the active voice will emphasize
    the person or thing who is performing an action (eg.The dog chased the ball).  In contrast, the passive voice will highlight
    the recipient of the action (The ball was chased by the dog). Therefore use the passive voice, only when it's less important
    who or what completed the action and more important that the action was completed. For example:

    - Recommended: The key-auth plugin authenticates the requests.
    - Not recommended: The requests are authenticated by the key-auth plugin.

* Capitalization:

    * For titles of a section, capitalize the first letter of each word except for the [closed-class words](https://en.wikipedia.org/wiki/Part_of_speech#Open_and_closed_classes)
      such as determiners, pronouns, conjunctions, and prepositions. Use the following [link](https://capitalizemytitle.com/#Chicago) for guidance.
      - Recommended: Authentication **with** APISIX

    * For normal sentences, don't [capitalize](https://www.grammarly.com/blog/capitalization-rules/) random words in the middle of the sentences.
      Use the Chicago manual for capitalization rules for the documentation.

* Second Person

    In general, use second person in your docs rather than first person. For example:

    - Recommended: You are recommended to use the docker based deployment.
    - Not Recommended: We recommend to use the docker based deployment.

* Spellings

    Use [American spellings](https://www.oxfordinternationalenglish.com/differences-in-british-and-american-spelling/) when
    contributing to the documentation.

* Voice

    * Use a friendly and conversational tone. Always use simple sentences. If the sentence is lengthy try to break it in to smaller sentences.

## Check code style and test case style

* code style
    * Please take a look at [APISIX Lua Coding Style Guide](CODE_STYLE.md).
    * Use tool to check your code statically by command: `make lint`.

```shell
        # install `luacheck` first before run it
        $ luarocks install luacheck
        # check source code
        $ make lint
        ./utils/check-lua-code-style.sh
        + luacheck -q apisix t/lib
        Total: 0 warnings / 0 errors in 146 files
        + find apisix -name *.lua ! -wholename apisix/cli/ngx_tpl.lua -exec ./utils/lj-releng {} +
        + grep -E ERROR.*.lua: /tmp/check.log
        + true
        + [ -s /tmp/error.log ]
        ./utils/check-test-code-style.sh
        + find t -name '*.t' -exec grep -E '\-\-\-\s+(SKIP|ONLY|LAST|FIRST)$' '{}' +
        + true
        + '[' -s /tmp/error.log ']'
        + find t -name '*.t' -exec ./utils/reindex '{}' +
        + grep done. /tmp/check.log
        + true
        + '[' -s /tmp/error.log ']'
```

      The `lj-releng` and `reindex` will be downloaded automatically by `make lint` if not exists.

* test case style
    * Use tool to check your test case style statically by command, eg: `make lint`.
    * When the test file is too large, for example > 800 lines, you should split it to a new file.
      Please take a look at `t/plugin/limit-conn.t` and `t/plugin/limit-conn2.t`.
    * For more details, see the [testing framework](https://github.com/apache/apisix/blob/master/docs/en/latest/internal/testing-framework.md)

## Contributor T-shirt

If you have contributed to Apache APISIX, no matter it is a code contribution to fix a bug or a feature request, or a documentation change, Congratulations! You are eligible to receive the very special Contributor T-shirt! It's always been the community effort that has made Apache APISIX be understood and used by more developers. Go ahead and fill out the [Contributors Submissions form](https://docs.google.com/forms/d/e/1FAIpQLSdXEpCs60UK49UlOGdBCQSXr7DYz3enyT4GJPKrYQmYfVLPKQ/viewform).

![Contributor T-shirt](https://static.apiseven.com/202108/1642392020136-19a7c07b-27de-4c29-9168-099532d2638f.jpg)

## Do you have questions about the source code?

- **QQ Group**: 781365357(recommended), 578997126, 552030619
- Join in `apisix` channel at [Apache Slack](http://s.apache.org/slack-invite). If the link is not working, find the latest one at [Apache INFRA WIKI](https://cwiki.apache.org/confluence/display/INFRA/Slack+Guest+Invites).
