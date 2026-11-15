using System.Text;
using System.Text.Json;

namespace BKE.Licensing.Verification;

public static class StrictJsonParser
{
    private const int MaxDepth = 32;
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    public static bool TryParseUnambiguous(ReadOnlySpan<byte> utf8Bytes, out JsonDocument? document)
    {
        document = null;
        if (utf8Bytes.IsEmpty)
        {
            return false;
        }

        // Explicitly reject UTF-8 BOM (0xEF 0xBB 0xBF) or decoded leading U+FEFF.
        if (utf8Bytes.Length >= 3 &&
            utf8Bytes[0] == 0xEF &&
            utf8Bytes[1] == 0xBB &&
            utf8Bytes[2] == 0xBF)
        {
            return false;
        }

        try
        {
            // Throws DecoderFallbackException on overlong encodings, lone surrogates, or truncated sequences.
            var text = StrictUtf8.GetString(utf8Bytes);
            if (text.Length > 0 && text[0] == '\uFEFF')
            {
                return false;
            }

            var readerOptions = new JsonReaderOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = MaxDepth,
            };

            var reader = new Utf8JsonReader(utf8Bytes, isFinalBlock: true, new JsonReaderState(readerOptions));
            var objectKeys = new Stack<HashSet<string>>();

            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.StartObject:
                        if (reader.CurrentDepth >= MaxDepth)
                        {
                            return false;
                        }
                        objectKeys.Push(new HashSet<string>(StringComparer.Ordinal));
                        break;

                    case JsonTokenType.EndObject:
                        if (objectKeys.Count == 0)
                        {
                            return false;
                        }
                        objectKeys.Pop();
                        break;

                    case JsonTokenType.PropertyName:
                        if (objectKeys.Count == 0)
                        {
                            return false;
                        }
                        var propertyName = reader.GetString();
                        if (propertyName is null || !objectKeys.Peek().Add(propertyName))
                        {
                            return false;
                        }
                        break;
                }
            }

            if (reader.BytesConsumed != utf8Bytes.Length)
            {
                return false;
            }

            document = JsonDocument.Parse(
                utf8Bytes.ToArray(),
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = MaxDepth,
                });
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }
}
