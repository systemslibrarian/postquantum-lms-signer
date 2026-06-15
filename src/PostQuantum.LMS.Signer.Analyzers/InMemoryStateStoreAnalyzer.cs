using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace PostQuantum.Lms.Analyzers
{
    /// <summary>
    /// Reports <c>PQLMS001</c> when <c>InMemoryStateStore</c> is instantiated. The in-memory store is not
    /// crash-safe and loses its state on process exit, so using it for a persistent signing key risks
    /// one-time-key reuse after a restart.
    /// </summary>
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public sealed class InMemoryStateStoreAnalyzer : DiagnosticAnalyzer
    {
        /// <summary>The diagnostic id for the in-memory-state-store rule.</summary>
        public const string DiagnosticId = "PQLMS001";

        private const string TargetTypeName = "InMemoryStateStore";

        private static readonly DiagnosticDescriptor Rule = new DiagnosticDescriptor(
            id: DiagnosticId,
            title: "InMemoryStateStore is not crash-safe",
            messageFormat: "InMemoryStateStore is not crash-safe; do not use it for a persistent signing key",
            category: "Security",
            defaultSeverity: DiagnosticSeverity.Warning,
            isEnabledByDefault: true,
            description: "InMemoryStateStore loses its state when the process exits. Backing a persistent " +
                         "LMS/HSS signing key with it can lead to one-time-key reuse after a crash or restart. " +
                         "Use a crash-safe store such as FileStateStore for any key that outlives the process.");

        /// <inheritdoc />
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
            ImmutableArray.Create(Rule);

        // TODO: PQLMS002 — flag a call to HssSigner/LmsSigner SignAsync whose Task is not awaited
        //       (fire-and-forget signing can race state persistence).
        // TODO: PQLMS003 — flag reuse of the same keyId across two CreateAsync calls in the same scope.

        /// <inheritdoc />
        public override void Initialize(AnalysisContext context)
        {
            if (context == null)
            {
                throw new System.ArgumentNullException(nameof(context));
            }

            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
            context.EnableConcurrentExecution();
            context.RegisterSyntaxNodeAction(AnalyzeObjectCreation, SyntaxKind.ObjectCreationExpression);
        }

        private static void AnalyzeObjectCreation(SyntaxNodeAnalysisContext context)
        {
            var creation = (ObjectCreationExpressionSyntax)context.Node;
            string typeName = GetSimpleTypeName(creation.Type);
            if (typeName != TargetTypeName)
            {
                return;
            }

            context.ReportDiagnostic(Diagnostic.Create(Rule, creation.GetLocation()));
        }

        private static string GetSimpleTypeName(TypeSyntax type)
        {
            switch (type)
            {
                case IdentifierNameSyntax identifier:
                    return identifier.Identifier.ValueText;
                case QualifiedNameSyntax qualified:
                    return qualified.Right.Identifier.ValueText;
                case GenericNameSyntax generic:
                    return generic.Identifier.ValueText;
                default:
                    return type.ToString();
            }
        }
    }
}
