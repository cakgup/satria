# The following licence only applies to this file:
# Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:

# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.

# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""
This class is a rewrite based on the JS implementation found here:
https://github.com/RedHatProductSecurity/cvss-v4-calculator

Implements class for CVSS4 specification as defined at
https://www.first.org/cvss/specification-document .

The library is compatible with both Python 2 and Python 3.
"""

# Match the vendored FIRST JavaScript reference rounding exactly.
# Derived from cvss 3.6; only final rounding differs.
from math import floor
from cvss import CVSS4
from cvss.constants4 import CVSS_LOOKUP_GLOBAL, MAX_SEVERITY


class ReferenceCVSS4(CVSS4):
    def compute_base_score(self):
        AV_levels = {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
        PR_levels = {"N": 0.0, "L": 0.1, "H": 0.2}
        UI_levels = {"N": 0.0, "P": 0.1, "A": 0.2}

        AC_levels = {"L": 0.0, "H": 0.1}
        AT_levels = {"N": 0.0, "P": 0.1}

        VC_levels = {"H": 0.0, "L": 0.1, "N": 0.2}
        VI_levels = {"H": 0.0, "L": 0.1, "N": 0.2}
        VA_levels = {"H": 0.0, "L": 0.1, "N": 0.2}

        SC_levels = {"H": 0.1, "L": 0.2, "N": 0.3}
        SI_levels = {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
        SA_levels = {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}

        CR_levels = {"H": 0.0, "M": 0.1, "L": 0.2}
        IR_levels = {"H": 0.0, "M": 0.1, "L": 0.2}
        AR_levels = {"H": 0.0, "M": 0.1, "L": 0.2}

        # E_levels = {"U": 0.2, "P": 0.1, "A": 0}

        macroVector = self.macroVector()

        if all([self.m(metric) == "N" for metric in ["VC", "VI", "VA", "SC", "SI", "SA"]]):
            self.base_score = 0.0
            return
        value = CVSS_LOOKUP_GLOBAL[macroVector]

        eq1_val = int(macroVector[0])
        eq2_val = int(macroVector[1])
        eq3_val = int(macroVector[2])
        eq4_val = int(macroVector[3])
        eq5_val = int(macroVector[4])
        eq6_val = int(macroVector[5])

        eq1_next_lower_macro = "".join(
            str(val) for val in [eq1_val + 1, eq2_val, eq3_val, eq4_val, eq5_val, eq6_val]
        )
        eq2_next_lower_macro = "".join(
            str(val) for val in [eq1_val, eq2_val + 1, eq3_val, eq4_val, eq5_val, eq6_val]
        )

        if eq3_val == 1 and eq6_val == 1:
            eq3eq6_next_lower_macro = "".join(
                str(val) for val in [eq1_val, eq2_val, eq3_val + 1, eq4_val, eq5_val, eq6_val]
            )
        elif eq3_val == 0 and eq6_val == 1:
            eq3eq6_next_lower_macro = "".join(
                str(val) for val in [eq1_val, eq2_val, eq3_val + 1, eq4_val, eq5_val, eq6_val]
            )
        elif eq3_val == 1 and eq6_val == 0:
            eq3eq6_next_lower_macro = "".join(
                str(val) for val in [eq1_val, eq2_val, eq3_val, eq4_val, eq5_val, eq6_val + 1]
            )
        elif eq3_val == 0 and eq6_val == 0:
            eq3eq6_next_lower_macro_left = "".join(
                str(val) for val in [eq1_val, eq2_val, eq3_val, eq4_val, eq5_val, eq6_val + 1]
            )
            eq3eq6_next_lower_macro_right = "".join(
                str(val) for val in [eq1_val, eq2_val, eq3_val + 1, eq4_val, eq5_val, eq6_val]
            )
        else:
            eq3eq6_next_lower_macro = "".join(
                str(val) for val in [eq1_val, eq2_val, eq3_val + 1, eq4_val, eq5_val, eq6_val + 1]
            )

        eq4_next_lower_macro = "".join(
            str(val) for val in [eq1_val, eq2_val, eq3_val, eq4_val + 1, eq5_val, eq6_val]
        )
        eq5_next_lower_macro = "".join(
            str(val) for val in [eq1_val, eq2_val, eq3_val, eq4_val, eq5_val + 1, eq6_val]
        )

        score_eq1_next_lower_macro = CVSS_LOOKUP_GLOBAL.get(eq1_next_lower_macro, float("nan"))
        score_eq2_next_lower_macro = CVSS_LOOKUP_GLOBAL.get(eq2_next_lower_macro, float("nan"))

        if eq3_val == 0 and eq6_val == 0:
            score_eq3eq6_next_lower_macro_left = CVSS_LOOKUP_GLOBAL.get(
                eq3eq6_next_lower_macro_left, float("nan")
            )
            score_eq3eq6_next_lower_macro_right = CVSS_LOOKUP_GLOBAL.get(
                eq3eq6_next_lower_macro_right, float("nan")
            )

            score_eq3eq6_next_lower_macro = max(
                score_eq3eq6_next_lower_macro_left, score_eq3eq6_next_lower_macro_right
            )
        else:
            score_eq3eq6_next_lower_macro = CVSS_LOOKUP_GLOBAL.get(
                eq3eq6_next_lower_macro, float("nan")
            )

        score_eq4_next_lower_macro = CVSS_LOOKUP_GLOBAL.get(eq4_next_lower_macro, float("nan"))
        score_eq5_next_lower_macro = CVSS_LOOKUP_GLOBAL.get(eq5_next_lower_macro, float("nan"))

        eq1_maxes = self.get_eq_maxes(macroVector, 1)
        eq2_maxes = self.get_eq_maxes(macroVector, 2)
        eq3_eq6_maxes = self.get_eq_maxes(macroVector, 3)[macroVector[5]]
        eq4_maxes = self.get_eq_maxes(macroVector, 4)
        eq5_maxes = self.get_eq_maxes(macroVector, 5)

        max_vectors = []
        for eq1_max in eq1_maxes:
            for eq2_max in eq2_maxes:
                for eq3_eq6_max in eq3_eq6_maxes:
                    for eq4_max in eq4_maxes:
                        for eq5max in eq5_maxes:
                            max_vectors.append(eq1_max + eq2_max + eq3_eq6_max + eq4_max + eq5max)

        for max_vector in max_vectors:
            severity_distance_AV = (
                AV_levels[self.m("AV")] - AV_levels[self.extract_value_metric("AV", max_vector)]
            )
            severity_distance_PR = (
                PR_levels[self.m("PR")] - PR_levels[self.extract_value_metric("PR", max_vector)]
            )
            severity_distance_UI = (
                UI_levels[self.m("UI")] - UI_levels[self.extract_value_metric("UI", max_vector)]
            )
            severity_distance_AC = (
                AC_levels[self.m("AC")] - AC_levels[self.extract_value_metric("AC", max_vector)]
            )
            severity_distance_AT = (
                AT_levels[self.m("AT")] - AT_levels[self.extract_value_metric("AT", max_vector)]
            )
            severity_distance_VC = (
                VC_levels[self.m("VC")] - VC_levels[self.extract_value_metric("VC", max_vector)]
            )
            severity_distance_VI = (
                VI_levels[self.m("VI")] - VI_levels[self.extract_value_metric("VI", max_vector)]
            )
            severity_distance_VA = (
                VA_levels[self.m("VA")] - VA_levels[self.extract_value_metric("VA", max_vector)]
            )
            severity_distance_SC = (
                SC_levels[self.m("SC")] - SC_levels[self.extract_value_metric("SC", max_vector)]
            )
            severity_distance_SI = (
                SI_levels[self.m("SI")] - SI_levels[self.extract_value_metric("SI", max_vector)]
            )
            severity_distance_SA = (
                SA_levels[self.m("SA")] - SA_levels[self.extract_value_metric("SA", max_vector)]
            )
            severity_distance_CR = (
                CR_levels[self.m("CR")] - CR_levels[self.extract_value_metric("CR", max_vector)]
            )
            severity_distance_IR = (
                IR_levels[self.m("IR")] - IR_levels[self.extract_value_metric("IR", max_vector)]
            )
            severity_distance_AR = (
                AR_levels[self.m("AR")] - AR_levels[self.extract_value_metric("AR", max_vector)]
            )

            if any(
                [
                    met < 0
                    for met in [
                        severity_distance_AV,
                        severity_distance_PR,
                        severity_distance_UI,
                        severity_distance_AC,
                        severity_distance_AT,
                        severity_distance_VC,
                        severity_distance_VI,
                        severity_distance_VA,
                        severity_distance_SC,
                        severity_distance_SI,
                        severity_distance_SA,
                        severity_distance_CR,
                        severity_distance_IR,
                        severity_distance_AR,
                    ]
                ]
            ):
                continue
            break

        current_severity_distance_eq1 = (
            severity_distance_AV + severity_distance_PR + severity_distance_UI
        )
        current_severity_distance_eq2 = severity_distance_AC + severity_distance_AT
        current_severity_distance_eq3eq6 = (
            severity_distance_VC
            + severity_distance_VI
            + severity_distance_VA
            + severity_distance_CR
            + severity_distance_IR
            + severity_distance_AR
        )
        current_severity_distance_eq4 = (
            severity_distance_SC + severity_distance_SI + severity_distance_SA
        )
        # current_severity_distance_eq5 = 0

        step = 0.1

        available_distance_eq1 = value - score_eq1_next_lower_macro
        available_distance_eq2 = value - score_eq2_next_lower_macro
        available_distance_eq3eq6 = value - score_eq3eq6_next_lower_macro
        available_distance_eq4 = value - score_eq4_next_lower_macro
        available_distance_eq5 = value - score_eq5_next_lower_macro

        percent_to_next_eq1_severity = 0
        percent_to_next_eq2_severity = 0
        percent_to_next_eq3eq6_severity = 0
        percent_to_next_eq4_severity = 0
        percent_to_next_eq5_severity = 0

        n_existing_lower = 0

        normalized_severity_eq1 = 0
        normalized_severity_eq2 = 0
        normalized_severity_eq3eq6 = 0
        normalized_severity_eq4 = 0
        normalized_severity_eq5 = 0

        max_severity_eq1 = MAX_SEVERITY["eq1"][eq1_val] * step
        max_severity_eq2 = MAX_SEVERITY["eq2"][eq2_val] * step
        max_severity_eq3eq6 = MAX_SEVERITY["eq3eq6"][eq3_val][eq6_val] * step
        max_severity_eq4 = MAX_SEVERITY["eq4"][eq4_val] * step
        if type(available_distance_eq1) in (float, int) and available_distance_eq1 >= 0:
            n_existing_lower += 1
            percent_to_next_eq1_severity = (current_severity_distance_eq1) / max_severity_eq1
            normalized_severity_eq1 = available_distance_eq1 * percent_to_next_eq1_severity

        if type(available_distance_eq2) in (float, int) and available_distance_eq2 >= 0:
            n_existing_lower += 1
            percent_to_next_eq2_severity = (current_severity_distance_eq2) / max_severity_eq2
            normalized_severity_eq2 = available_distance_eq2 * percent_to_next_eq2_severity

        if type(available_distance_eq3eq6) in (float, int) and available_distance_eq3eq6 >= 0:
            n_existing_lower += 1
            percent_to_next_eq3eq6_severity = (
                current_severity_distance_eq3eq6
            ) / max_severity_eq3eq6
            normalized_severity_eq3eq6 = available_distance_eq3eq6 * percent_to_next_eq3eq6_severity

        if type(available_distance_eq4) in (float, int) and available_distance_eq4 >= 0:
            n_existing_lower += 1
            percent_to_next_eq4_severity = (current_severity_distance_eq4) / max_severity_eq4
            normalized_severity_eq4 = available_distance_eq4 * percent_to_next_eq4_severity

        if type(available_distance_eq5) in (float, int) and available_distance_eq5 >= 0:
            n_existing_lower += 1
            percent_to_next_eq5_severity = 0
            normalized_severity_eq5 = available_distance_eq5 * percent_to_next_eq5_severity

        mean_distance = (
            0
            if n_existing_lower == 0
            else (
                normalized_severity_eq1
                + normalized_severity_eq2
                + normalized_severity_eq3eq6
                + normalized_severity_eq4
                + normalized_severity_eq5
            )
            / n_existing_lower
        )

        value -= mean_distance
        value = max(0.0, value)
        value = min(10.0, value)

        self.base_score = floor(value * 10 + 0.5) / 10
