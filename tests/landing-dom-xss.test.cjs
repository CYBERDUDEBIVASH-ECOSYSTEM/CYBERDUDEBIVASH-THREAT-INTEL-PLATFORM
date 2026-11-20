'use strict';
// P0: Network/API-provided checkout text must never be interpreted as markup.
// Node's built-in VM and fake DOM keep this test offline and dependency-free.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function bootstrap() {
  const ids = new Map();
  function element(tag) {
    const el = {
      tagName: tag.toUpperCase(), style: {}, children: [], attributes: {},
      className: '', id: '', textContent: '', listeners: {},
      appendChild(child) { this.children.push(child); if (child.id) ids.set(child.id, child); return child; },
      replaceChildren(...children) { this.children = [...children]; },
      setAttribute(name, value) { this.attributes[name] = value; },
      addEventListener(name, cb) { this.listeners[name] = cb; },
      remove() {},
    };
    Object.defineProperty(el, 'innerHTML', {
      set() { throw new Error('UNSAFE_HTML_SINK_EXECUTED'); },
      get() { return ''; },
    });
    return el;
  }
  const body = element('body');
  const document = {
    body,
    createElement: element,
    getElementById(id) { return ids.get(id) || null; },
    addEventListener() {}, // Do not start cosmetic DOM-ready behavior.
  };
  const window = {};
  const source = fs.readFileSync(path.join(__dirname, '..', 'landing', 'script.js'), 'utf8');
  vm.runInNewContext(source + '\nwindow.__testSafeCheckoutUrl = safeCheckoutUrl;',
    { document, window, setTimeout() {}, console, URL }, {
      filename: 'landing/script.js', timeout: 3000,
    });
  return { window, body, ids };
}

test('API-supplied checkout error is rendered as inert text', () => {
  const { window, body } = bootstrap();
  const attack = '<img src=x onerror=alert(1)>';
  window.APEX_UI.Toast.error(attack);
  const toastContainer = body.children.find(c => c.id === 'toast-container');
  assert.ok(toastContainer);
  assert.equal(toastContainer.children.length, 1);
  const toast = toastContainer.children[0];
  assert.equal(toast.children.length, 2);
  assert.equal(toast.children[1].textContent, attack);
  assert.equal(toast.children[1].children.length, 0);
});

test('provider name cannot alter toast markup', () => {
  const { window, body } = bootstrap();
  const provider = '</span><svg onload=alert(1)>';
  window.APEX_UI.Toast.success(`Redirecting to ${provider} checkout...`);
  const toast = body.children.find(c => c.id === 'toast-container').children[0];
  assert.equal(toast.children[1].textContent, `Redirecting to ${provider} checkout...`);
  assert.equal(toast.children.length, 2);
});

test('error banner renders payload as inert text and permits only approved support URL', () => {
  const { window, ids } = bootstrap();
  const payload = '<svg onload=alert(1)>';
  window.ErrorBanner.show(payload, 0, {
    href: 'https://tools.cyberdudebivash.com/', label: 'Gumroad store',
  });
  const banner = ids.get('error-banner');
  assert.ok(banner);
  assert.equal(banner.children[1].textContent, payload);
  const link = banner.children.find(c => c.tagName === 'A');
  assert.equal(link.href, 'https://tools.cyberdudebivash.com/');
  assert.equal(link.rel, 'noopener noreferrer');
  assert.equal(link.target, '_blank');
  const close = banner.children.find(c => c.tagName === 'BUTTON');
  assert.equal(typeof close.listeners.click, 'function');
  close.listeners.click();
  assert.equal(banner.style.display, 'none');
});

test('error banner rejects an unapproved outbound support link', () => {
  const { window, ids } = bootstrap();
  window.ErrorBanner.show('Try support', 0, {
    href: 'https://attacker.example/', label: '<img src=x>',
  });
  const banner = ids.get('error-banner');
  assert.equal(banner.children.filter(c => c.tagName === 'A').length, 0);
});

test('legacy checkout accepts only approved HTTPS payment destinations', () => {
  const { window } = bootstrap();
  const verify = window.__testSafeCheckoutUrl;
  for (const approved of [
    'https://checkout.razorpay.com/pay/checkout123',
    'https://checkout.stripe.com/c/pay/checkout123',
    'https://gumroad.com/l/official-product',
    'https://tools.cyberdudebivash.com/',
  ]) {
    assert.equal(verify(approved), approved);
  }
  for (const unsafe of [
    'javascript:alert(1)',
    'data:text/html,<img src=x onerror=alert(1)>',
    'http://checkout.stripe.com/pay',
    'https://checkout.stripe.com.evil.example/pay',
    'https://user:pass@checkout.razorpay.com/pay',
    'https://attacker.example/pay',
    '//checkout.stripe.com/pay',
    'https://checkout.stripe.com:444/pay',
    '/relative-checkout',
    '',
  ]) {
    assert.equal(verify(unsafe), null, unsafe);
  }
});
