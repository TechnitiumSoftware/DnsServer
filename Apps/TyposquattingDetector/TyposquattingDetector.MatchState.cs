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

using System.Collections.Concurrent;

namespace TyposquattingDetector
{
     public partial class TyposquattingDetector
    {
        // Define the state as a class to allow locking
        private class MatchState
        {
            public string? BestDomain;
            public int BestScore;

            // Reset method for reuse
            public void Reset()
            {
                BestDomain = null;
                BestScore = 0;
            }
        }

        // Simple thread-safe pool
        private readonly ConcurrentQueue<MatchState> _statePool = new ConcurrentQueue<MatchState>();

        private MatchState GetState()
        {
            if (_statePool.TryDequeue(out var state)) return state;
            return new MatchState();
        }

        private void ReturnState(MatchState state)
        {
            state.Reset();
            _statePool.Enqueue(state);
        }
    }
}