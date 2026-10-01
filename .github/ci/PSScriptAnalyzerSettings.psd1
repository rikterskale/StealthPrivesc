@{
    IncludeRules = @(
        'PSAvoidUsingInvokeExpression'
        'PSAvoidUsingConvertToSecureStringWithPlainText'
        'PSAvoidUsingPlainTextForPassword'
        'PSAvoidUsingUsernameAndPasswordParams'
        'PSAvoidUsingBrokenHashAlgorithms'
        'PSAvoidUsingComputerNameHardcoded'
        'PSUseDeclaredVarsMoreThanAssignments'
    )
    # Correctness rules are required. Formatting is deliberately not a rewrite gate.
}
