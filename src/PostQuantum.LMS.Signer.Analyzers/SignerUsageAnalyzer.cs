using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace PostQuantum.Lms.Analyzers
{
    /// <summary>
    /// Reports usage footguns on the LMS/HSS signer types:
    /// <list type="bullet">
    /// <item><c>PQLMS002</c> — a fire-and-forget call to <c>SignAsync</c> whose <c>Task</c> is discarded.</item>
    /// <item><c>PQLMS003</c> — a call to the synchronous <c>Sign(byte[])</c> wrapper.</item>
    /// </list>
    /// Both rules use the semantic model to match the signer types by their full display name, so the
    /// analyzer needs no compile-time reference to the signer assemblies.
    /// </summary>
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public sealed class SignerUsageAnalyzer : DiagnosticAnalyzer
    {
        /// <summary>The diagnostic id for the un-awaited SignAsync rule.</summary>
        public const string UnawaitedSignAsyncDiagnosticId = "PQLMS002";

        /// <summary>The diagnostic id for the synchronous Sign rule.</summary>
        public const string SynchronousSignDiagnosticId = "PQLMS003";

        private const string HelpLinkUri = "https://github.com/systemslibrarian/postquantum-lms-signer";

        // Full type display strings the rules match against (no hard reference needed).
        private const string HssSignerTypeName = "PostQuantum.Lms.HssSigner";
        private const string LmsSignerTypeName = "PostQuantum.Lms.LmsSigner";
        private const string SigningServiceTypeName = "PostQuantum.Lms.AspNetCore.ILmsSigningService";

        private static readonly DiagnosticDescriptor UnawaitedSignAsyncRule = new DiagnosticDescriptor(
            id: UnawaitedSignAsyncDiagnosticId,
            title: "SignAsync result is not awaited",
            messageFormat: "The Task returned by SignAsync is not awaited; the signature and persisted key-index state may be lost",
            category: "Reliability",
            defaultSeverity: DiagnosticSeverity.Warning,
            isEnabledByDefault: true,
            description: "The signer persists the one-time-key index before returning the signature. Dropping the " +
                         "Task from SignAsync (fire-and-forget) can lose signatures and swallow state-persistence " +
                         "errors. Await the Task (or otherwise observe it) so failures surface and state stays consistent.",
            helpLinkUri: HelpLinkUri);

        private static readonly DiagnosticDescriptor SynchronousSignRule = new DiagnosticDescriptor(
            id: SynchronousSignDiagnosticId,
            title: "Prefer SignAsync over the synchronous Sign()",
            messageFormat: "Prefer the asynchronous SignAsync over the synchronous Sign(); the sync wrapper blocks on async I/O and can deadlock",
            category: "Reliability",
            defaultSeverity: DiagnosticSeverity.Info,
            isEnabledByDefault: true,
            description: "The synchronous Sign(byte[]) wrapper blocks on the underlying async I/O used to persist the " +
                         "one-time-key index, which can deadlock in async contexts. Prefer awaiting SignAsync instead.",
            helpLinkUri: HelpLinkUri);

        /// <inheritdoc />
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
            ImmutableArray.Create(UnawaitedSignAsyncRule, SynchronousSignRule);

        /// <inheritdoc />
        public override void Initialize(AnalysisContext context)
        {
            if (context == null)
            {
                throw new System.ArgumentNullException(nameof(context));
            }

            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
            context.EnableConcurrentExecution();
            context.RegisterSyntaxNodeAction(AnalyzeInvocation, SyntaxKind.InvocationExpression);
        }

        private static void AnalyzeInvocation(SyntaxNodeAnalysisContext context)
        {
            var invocation = (InvocationExpressionSyntax)context.Node;
            string methodName = GetInvokedMethodName(invocation.Expression);
            if (methodName != "SignAsync" && methodName != "Sign")
            {
                return;
            }

            if (!(context.SemanticModel.GetSymbolInfo(invocation, context.CancellationToken).Symbol is IMethodSymbol method))
            {
                // Symbol could not be resolved — do not guess.
                return;
            }

            INamedTypeSymbol containingTypeSymbol = method.ContainingType;
            if (containingTypeSymbol == null)
            {
                return;
            }

            string containingType = containingTypeSymbol.ToDisplayString();

            if (methodName == "SignAsync")
            {
                AnalyzeSignAsync(context, invocation, method, containingType);
            }
            else
            {
                AnalyzeSign(context, invocation, method, containingType);
            }
        }

        private static void AnalyzeSignAsync(
            SyntaxNodeAnalysisContext context,
            InvocationExpressionSyntax invocation,
            IMethodSymbol method,
            string containingType)
        {
            if (containingType != HssSignerTypeName &&
                containingType != LmsSignerTypeName &&
                containingType != SigningServiceTypeName)
            {
                return;
            }

            // Only flag when the invocation is the direct expression of an expression statement,
            // i.e. the result is discarded: not awaited, not assigned, not returned, not an argument.
            if (!(invocation.Parent is ExpressionStatementSyntax statement) || statement.Expression != invocation)
            {
                return;
            }

            context.ReportDiagnostic(Diagnostic.Create(UnawaitedSignAsyncRule, invocation.GetLocation()));
        }

        private static void AnalyzeSign(
            SyntaxNodeAnalysisContext context,
            InvocationExpressionSyntax invocation,
            IMethodSymbol method,
            string containingType)
        {
            if (containingType != HssSignerTypeName && containingType != LmsSignerTypeName)
            {
                return;
            }

            // Only the instance Sign(message) wrapper; never the static Verify (or any static method).
            if (method.IsStatic)
            {
                return;
            }

            context.ReportDiagnostic(Diagnostic.Create(SynchronousSignRule, invocation.GetLocation()));
        }

        private static string GetInvokedMethodName(ExpressionSyntax expression)
        {
            switch (expression)
            {
                case MemberAccessExpressionSyntax memberAccess:
                    return memberAccess.Name.Identifier.ValueText;
                case MemberBindingExpressionSyntax memberBinding:
                    return memberBinding.Name.Identifier.ValueText;
                case IdentifierNameSyntax identifier:
                    return identifier.Identifier.ValueText;
                case GenericNameSyntax generic:
                    return generic.Identifier.ValueText;
                default:
                    return string.Empty;
            }
        }
    }
}
