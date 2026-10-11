"""Response fixtures shaped like DVGA 2.2.0 (Damn Vulnerable GraphQL Application) answers.

Plain data with no imports, shared by tests in both import layouts.
"""

# What DVGA 2.2.0 answers (trimmed): the query root, its fields and the type list.
DVGA_INTROSPECTION = {"data": {"__schema": {
    "queryType": {"name": "Query", "fields": [
        {"name": "pastes"}, {"name": "paste"}, {"name": "systemUpdate"},
        {"name": "deleteAllPastes"}, {"name": "me"},
    ]},
    "types": [{"name": "Query"}, {"name": "PasteObject"}, {"name": "String"},
              {"name": "__Schema"}, {"name": "Mutations"}],
}}}
DVGA_GRAPHIQL = b"""<!--
The request to this GraphQL server provided the header "Accept: text/html"
and as a result has been presented GraphiQL - an in-browser IDE for exploring GraphQL.
-->
<!DOCTYPE html><html><head><title>GraphiQL</title>
<link href="//cdn.jsdelivr.net/npm/graphiql@0.11.11/graphiql.css" rel="stylesheet" />
<script src="//cdn.jsdelivr.net/npm/graphiql@0.11.11/graphiql.min.js"></script></head>
<body><script>function graphQLFetcher(graphQLParams) { return fetch('/graphql'); }
ReactDOM.render(React.createElement(GraphiQL, {fetcher: graphQLFetcher}), document.body);
</script></body></html>"""
SPA_SHELL = b'<!doctype html><html><head><title>App</title></head><body><div id="root"></div><script src="/static/js/main.4f1c.js"></script></body></html>'
