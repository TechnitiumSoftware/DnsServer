/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)
Copyright (C) 2025  Zafer Balkan (zafer@zaferbalkan.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

using System;
using System.Collections.Concurrent;
using System.Threading;

namespace TyposquattingDetector
{
    public partial class TyposquattingDetector
    {
        // Bound the pool so burst traffic cannot cause permanent memory growth.
        // Size heuristic: a few multiples of CPU is enough to cover typical concurrency.
        private static readonly int MaxStatePoolSize = Math.Max(16, Environment.ProcessorCount * 4);

        private readonly ConcurrentQueue<MatchState> _statePool = new ConcurrentQueue<MatchState>();

        private int _statePoolCount;

        private MatchState GetState()
        {
            if (_statePool.TryDequeue(out MatchState? state))
            {
                Interlocked.Decrement(ref _statePoolCount);
                return state;
            }

            return new MatchState();
        }

        private void ReturnState(MatchState state)
        {
            state.Reset();

            int newCount = Interlocked.Increment(ref _statePoolCount);
            if (newCount <= MaxStatePoolSize)
            {
                _statePool.Enqueue(state);
                return;
            }

            // Over cap: undo the count and let GC reclaim this instance.
            Interlocked.Decrement(ref _statePoolCount);
        }

        // Define the state as a class to allow locking
        private sealed class MatchState
        {
            public string? BestDomain;
            public int BestScore;

            public void Reset()
            {
                BestDomain = null;
                BestScore = 0;
            }
        }
    }
}