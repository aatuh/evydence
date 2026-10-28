// Owned offline bridge to the pinned official Prometheus editor grammar/linter.
const fs = require('node:fs');
const path = require('node:path');
const {createRequire} = require('node:module');
const result = {schema: 'evydence-promql-facts.v1', valid: false, reason: 'unavailable'};
try {
  globalThis.fetch = () => { throw new Error('network-disabled'); };
  const req = createRequire(path.resolve(process.cwd(), 'package.json'));
  if (req('@prometheus-io/codemirror-promql/package.json').version !== '0.313.4') throw new Error('parser-version');
  const grammarPackage = JSON.parse(fs.readFileSync(path.resolve(path.dirname(req.resolve('@prometheus-io/lezer-promql')), '..', 'package.json'), 'utf8'));
  if (grammarPackage.version !== '0.313.4') throw new Error('grammar-version');
  const {EditorState} = req('@codemirror/state');
  const {syntaxTree} = req('@codemirror/language');
  const {PromQLExtension, promQLLanguage, LanguageType} = req('@prometheus-io/codemirror-promql');
  result.reason = 'invalid';
  const input = JSON.parse(fs.readFileSync(0, 'utf8'));
  if (typeof input.query !== 'string' || input.query.length === 0 || input.query.length > 16384) throw new Error('query-budget');
  const query = input.query;
  const extension = new PromQLExtension().activateCompletion(false);
  const state = EditorState.create({doc: query, extensions: [promQLLanguage(LanguageType.PromQL)]});
  const diagnostics = extension.getLinter().promQL()({state});
  extension.destroy();
  if (diagnostics.some(d => d.severity === 'error')) throw new Error('query-type');
  const tree = syntaxTree(state);
  if (!tree.topNode.firstChild) throw new Error('empty-query');
  const facts = {selectors: [], grouping: [], matching: [], calls: [], durations: [], strings: [], numbers: [], functions: [], unsupported: []};
  const text = node => state.sliceDoc(node.from, node.to);
  const isCounter = name => ['rate', 'irate', 'increase', 'resets'].includes(name);
  const functionName = node => node.getChild('FunctionIdentifier') ? text(node.getChild('FunctionIdentifier')) : '';
  const groupLabels = node => {
    const values = [];
    for (const group of node.getChildren('GroupingLabels')) {
      for (let child = group.firstChild; child; child = child.nextSibling) values.push(text(child));
    }
    return values;
  };
  let count = 0;
  function walk(node, ancestors) {
    if (++count > 2048 || ancestors.length > 64 || node.type.isError) throw new Error('query-syntax-or-budget');
    if (node.name === 'VectorSelector') {
      const identifier = node.getChild('Identifier');
      const selector = {name: identifier ? text(identifier) : '', matchers: [], sum: false, counter: false};
      for (const parent of ancestors) {
        if (parent.name === 'AggregateExpr' && text(parent.getChild('AggregateOp')).toLowerCase() === 'sum') selector.sum = true;
        if (parent.name === 'FunctionCall' && isCounter(functionName(parent))) selector.counter = true;
      }
      const matchers = node.getChild('LabelMatchers');
      for (let child = matchers && matchers.firstChild; child; child = child.nextSibling) {
        if (child.name === 'QuotedLabelName') {
          selector.matchers.push({name: '__name__', value: text(child), op: '='});
        } else {
          const label = child.getChild('LabelName') || child.getChild('QuotedLabelName');
          const value = child.getChild('StringLiteral');
          const op = child.getChild('MatchOp');
          if (!label || !value || !op) throw new Error('matcher-shape');
          selector.matchers.push({name: text(label), value: text(value), op: text(op)});
        }
      }
      facts.selectors.push(selector);
    }
    if (node.name === 'AggregateExpr') {
      const modifier = node.getChild('AggregateModifier');
      if (modifier) facts.grouping.push(...groupLabels(modifier));
      if (['limitk', 'limit_ratio'].includes(text(node.getChild('AggregateOp')).toLowerCase())) facts.unsupported.push('experimental-aggregation');
    }
    if (node.name === 'MatchingModifierClause') facts.matching.push(...groupLabels(node));
    if (node.name === 'FunctionCall') {
      const name = functionName(node);
      facts.functions.push(name);
      if (isCounter(name)) {
        const args = node.getChild('FunctionCallBody');
        facts.calls.push({name, directMatrix: !!args && !!args.firstChild && args.firstChild.name === 'MatrixSelector'});
      }
    }
    if (node.name === 'StringLiteral' || node.name === 'QuotedLabelName') facts.strings.push(text(node));
    if (node.name === 'NumberDurationLiteral') facts.numbers.push(text(node));
    if (node.name === 'NumberDurationLiteralInDurationContext') {
      facts.durations.push({text: text(node), positive: !!node.parent && ['MatrixSelector', 'SubqueryExpr'].includes(node.parent.name)});
    }
    if (/^(Anchored|Smoothed|Fill|TrimUpper|TrimLower)/.test(node.name)) facts.unsupported.push('experimental-selector-or-fill');
    for (let child = node.firstChild; child; child = child.nextSibling) walk(child, ancestors.concat(node));
  }
  walk(tree.topNode, []);
  Object.assign(result, facts, {valid: true, reason: ''});
} catch {
  // Return only a fixed protocol outcome, never a parser/module error or query.
}
process.stdout.write(JSON.stringify(result));
