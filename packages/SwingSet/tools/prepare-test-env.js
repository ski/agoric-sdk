/**
 * Prepare Agoric SwingSet vat global environment for testing.
 *
 * installs SES (and does lockdown), plus adds mocks
 * for virtual objects: makeKind, makeWeakStore
 */
/* global globalThis */

// eslint-disable-next-line import/no-extraneous-dependencies
import { wrapTest } from '@agoric/ses-ava';
import '@agoric/install-ses';
// eslint-disable-next-line import/no-extraneous-dependencies
import rawTest from 'ava';
import { makeFakeVirtualObjectManager } from './fakeVirtualObjectManager';

const test = wrapTest(rawTest);
export default test;

const { makeKind, makeWeakStore } = makeFakeVirtualObjectManager(3);

globalThis.makeKind = makeKind;
globalThis.makeWeakStore = makeWeakStore;
