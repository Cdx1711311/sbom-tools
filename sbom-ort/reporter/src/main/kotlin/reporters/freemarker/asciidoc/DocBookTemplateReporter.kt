/*
 * Copyright (C) 2021 Bosch.IO GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * License-Filename: LICENSE
 */

package org.ossreviewtoolkit.reporter.reporters.freemarker.asciidoc

import org.ossreviewtoolkit.reporter.Reporter

/**
 * A [Reporter] that creates [DocBook][1] files from [Apache Freemarker][2] templates.
 *
 * [1]: https://docbook.org
 * [2]: https://freemarker.apache.org
 */
class DocBookTemplateReporter : AsciiDocTemplateReporter("docbook", "DocBookTemplate")
