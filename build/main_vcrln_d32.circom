pragma circom 2.1.6;
include "vcrln.circom";
component main {public [root, schema, epoch, community, x, ageCutoff, seniorityCutoff, baseLimit, verifiedBonus, seniorityBonus, mode]} = VCRLN(32);
