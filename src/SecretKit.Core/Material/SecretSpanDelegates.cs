namespace SecretKit.Core;

/// <summary>Consumes characters synchronously; the span is valid only during the callback.</summary>
/// <param name="span">A temporary material snapshot.</param>
public delegate void SecretSpanAction(ReadOnlySpan<char> span);

/// <summary>Consumes characters with caller-supplied state synchronously.</summary>
/// <typeparam name="TState">The caller's state type.</typeparam>
/// <param name="span">A temporary material snapshot valid only during the callback.</param>
/// <param name="state">Caller-supplied state.</param>
public delegate void SecretSpanAction<in TState>(ReadOnlySpan<char> span, TState state);

/// <summary>Projects characters synchronously; material copies in the result become caller-owned.</summary>
/// <typeparam name="TResult">The result type.</typeparam>
/// <param name="span">A temporary material snapshot valid only during the callback.</param>
/// <returns>The caller's result.</returns>
public delegate TResult SecretSpanFunc<out TResult>(ReadOnlySpan<char> span);

/// <summary>Projects characters with caller-supplied state synchronously.</summary>
/// <typeparam name="TState">The caller's state type.</typeparam>
/// <typeparam name="TResult">The result type.</typeparam>
/// <param name="span">A temporary material snapshot valid only during the callback.</param>
/// <param name="state">Caller-supplied state.</param>
/// <returns>The caller's result; any copied material becomes caller-owned.</returns>
public delegate TResult SecretSpanFunc<in TState, out TResult>(ReadOnlySpan<char> span, TState state);

/// <summary>Consumes UTF-8 synchronously; the span is valid only during the callback.</summary>
/// <param name="span">A temporary UTF-8 material snapshot.</param>
public delegate void SecretUtf8SpanAction(ReadOnlySpan<byte> span);

/// <summary>Consumes UTF-8 with caller-supplied state synchronously.</summary>
/// <typeparam name="TState">The caller's state type.</typeparam>
/// <param name="span">A temporary UTF-8 snapshot valid only during the callback.</param>
/// <param name="state">Caller-supplied state.</param>
public delegate void SecretUtf8SpanAction<in TState>(ReadOnlySpan<byte> span, TState state);

/// <summary>Projects UTF-8 synchronously; material copies in the result become caller-owned.</summary>
/// <typeparam name="TResult">The result type.</typeparam>
/// <param name="span">A temporary UTF-8 snapshot valid only during the callback.</param>
/// <returns>The caller's result.</returns>
public delegate TResult SecretUtf8SpanFunc<out TResult>(ReadOnlySpan<byte> span);

/// <summary>Projects UTF-8 with caller-supplied state synchronously.</summary>
/// <typeparam name="TState">The caller's state type.</typeparam>
/// <typeparam name="TResult">The result type.</typeparam>
/// <param name="span">A temporary UTF-8 snapshot valid only during the callback.</param>
/// <param name="state">Caller-supplied state.</param>
/// <returns>The caller's result; any copied material becomes caller-owned.</returns>
public delegate TResult SecretUtf8SpanFunc<in TState, out TResult>(ReadOnlySpan<byte> span, TState state);
