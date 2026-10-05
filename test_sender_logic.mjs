/**
 * CyberGuard regression harness for the Digital Impersonation sender rules.
 *
 * Run with:  node test_sender_logic.mjs
 *
 * The SENDER field accepts only an email address or a phone number, so
 * these checks exercise the real helpers inside script.js (sliced out of
 * the source, no DOM required) together with the demo scenario payload.
 */
import { readFileSync } from "node:fs";

const source = readFileSync("script.js", "utf8");

const start = source.indexOf("const IMPERSONATION_EMAIL_PATTERN");
const end = source.indexOf("function initializeDigitalImpersonation");

if (start < 0 || end < 0 || end < start) {
    console.error("could not locate sender helpers in script.js");
    process.exit(1);
}

const block = source.slice(start, end);

const factory = new Function(`${block}
    return { classifyImpersonationSender, normaliseImpersonationPhone, buildImpersonationMessage };
`);

const { classifyImpersonationSender, normaliseImpersonationPhone, buildImpersonationMessage } = factory();

const failures = [];
const expectKind = (input, expected) => {
    const actual = classifyImpersonationSender(input);
    if (actual !== expected) failures.push(`classify(${JSON.stringify(input)}) => ${actual}, expected ${expected}`);
};

// Accepted inputs
expectKind("alerts@secure-login.xyz", "email");
expectKind("  anil.verma@acme-corp.com ", "email");
expectKind("+91 98765 43210", "phone");
expectKind("+911234567890", "phone");
expectKind("98765 43210", "phone");
expectKind("(022) 4001-2345", "phone");

// Rejected inputs (names, malformed values, too-short numbers)
expectKind("", null);
expectKind("   ", null);
expectKind("IT Service Desk", null);
expectKind("Unknown", null);
expectKind("HR Admin", null);
expectKind("foo@bar", null);
expectKind("name@@company.com", null);
expectKind("12345", null);
expectKind("call me maybe", null);

// Phone normalisation groups separators for campaign clustering
if (normaliseImpersonationPhone("+91 98765 43210") !== "+919876543210") {
    failures.push(`normalise(+91 98765 43210) => ${normaliseImpersonationPhone("+91 98765 43210")}`);
}
if (normaliseImpersonationPhone("(022) 4001-2345") !== "02240012345") {
    failures.push(`normalise((022) 4001-2345) => ${normaliseImpersonationPhone("(022) 4001-2345")}`);
}

// Payload shape
const emailMessage = buildImpersonationMessage("alerts@sbi-netbanking-alert.xyz", "Your account will be suspended today.");
if (!emailMessage || emailMessage.channel !== "email") failures.push("email sender must produce channel=email");
if (emailMessage && emailMessage.sender_domain !== "sbi-netbanking-alert.xyz") failures.push(`email sender_domain => ${emailMessage?.sender_domain}`);
if (emailMessage && emailMessage.sender_name !== "alerts@sbi-netbanking-alert.xyz") failures.push(`email sender_name => ${emailMessage?.sender_name}`);

const phoneMessage = buildImpersonationMessage("+91 98765 43210", "URGENT notice: your account will be frozen.");
if (!phoneMessage || phoneMessage.channel !== "sms") failures.push("phone sender must produce channel=sms");
if (phoneMessage && phoneMessage.sender_domain !== "+919876543210") failures.push(`phone sender_domain => ${phoneMessage?.sender_domain}`);
if (phoneMessage && phoneMessage.sender_name !== "+919876543210") failures.push(`phone sender_name => ${phoneMessage?.sender_name}`);

if (buildImpersonationMessage("IT Service Desk", "hello") !== null) {
    failures.push("a display-name sender must not build a message");
}
if (buildImpersonationMessage("", "hello") !== null) {
    failures.push("an empty sender must not build a message");
}

// Demo scenario must satisfy the new sender rule
const demoSource = source.slice(source.indexOf("function loadImpersonationDemo"), source.indexOf("async function analyzeDigitalImpersonation"));
const demoMatch = demoSource.match(/const demoMessages = (\[[\s\S]*?\]);/);
if (!demoMatch) {
    failures.push("could not read demo messages from script.js");
} else {
    const demoMessages = new Function(`return ${demoMatch[1]}`)();
    if (demoMessages.length !== 6) failures.push(`demo should hold 6 messages, got ${demoMessages.length}`);
    demoMessages.forEach(message => {
        const kind = classifyImpersonationSender(message.sender_name);
        if (!kind) failures.push(`demo sender "${message.sender_name}" is not an email or phone number`);
        else if (kind === "email" && message.channel !== "email") failures.push(`demo ${message.message_id} email sender with channel ${message.channel}`);
        else if (kind === "phone" && message.channel !== "sms") failures.push(`demo ${message.message_id} phone sender with channel ${message.channel}`);
        if (kind === "email" && !message.sender_domain.includes(".")) failures.push(`demo ${message.message_id} missing sending domain`);
    });
}

if (failures.length) {
    console.log("FAILED CHECKS:");
    failures.forEach(item => console.log(" -", item));
    process.exit(1);
}

console.log("SENDER LOGIC CHECKS PASSED");
