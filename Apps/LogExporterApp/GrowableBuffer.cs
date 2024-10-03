using System;
using System.Buffers;

namespace LogExporter
{
    public class GrowableBuffer<T> : IBufferWriter<T>, IDisposable
    {
        // Gets the current length of the buffer contents
        public int Length => _position;

        // Initial capacity to be used in the constructor
        private const int DefaultInitialCapacity = 256;

        private Memory<T> _buffer;

        private int _position;

        private bool disposedValue;

        public GrowableBuffer(int initialCapacity = DefaultInitialCapacity)
        {
            _buffer = new Memory<T>(ArrayPool<T>.Shared.Rent(initialCapacity));
            _position = 0;
        }

        // IBufferWriter<T> implementation
        public void Advance(int count)
        {
            if (count < 0 || _position + count > _buffer.Length)
                throw new ArgumentOutOfRangeException(nameof(count));

            _position += count;
        }

        // Appends a single element to the buffer
        public void Append(T item)
        {
            EnsureCapacity(1);
            _buffer.Span[_position++] = item;
        }

        // Appends a span of elements to the buffer
        public void Append(ReadOnlySpan<T> span)
        {
            EnsureCapacity(span.Length);
            span.CopyTo(_buffer.Span[_position..]);
            _position += span.Length;
        }

        // Clears the buffer for reuse without reallocating
        public void Clear() => _position = 0;

        public Memory<T> GetMemory(int sizeHint = 0)
        {
            EnsureCapacity(sizeHint);
            return _buffer[_position..];
        }

        public Span<T> GetSpan(int sizeHint = 0)
        {
            EnsureCapacity(sizeHint);
            return _buffer.Span[_position..];
        }

        // Returns the buffer contents as an array
        public T[] ToArray()
        {
            T[] result = new T[_position];
            _buffer.Span[.._position].CopyTo(result);
            return result;
        }

        // Returns the buffer contents as a ReadOnlySpan<T>
        public ReadOnlySpan<T> ToSpan() => _buffer.Span[.._position];

        public override string ToString() => _buffer.Span[.._position].ToString();

        // Ensures the buffer has enough capacity to add more elements
        private void EnsureCapacity(int additionalCapacity)
        {
            if (_position + additionalCapacity > _buffer.Length)
            {
                GrowBuffer(_position + additionalCapacity);
            }
        }

        // Grows the buffer to accommodate the required capacity
        private void GrowBuffer(int requiredCapacity)
        {
            int newCapacity = Math.Max(_buffer.Length * 2, requiredCapacity);

            // Rent a larger buffer from the pool
            T[] newArray = ArrayPool<T>.Shared.Rent(newCapacity);
            Memory<T> newBuffer = new Memory<T>(newArray);

            // Copy current contents to the new buffer
            _buffer.Span[.._position].CopyTo(newBuffer.Span);

            // Return old buffer to the pool
            ArrayPool<T>.Shared.Return(_buffer.ToArray());

            // Assign the new buffer
            _buffer = newBuffer;
        }

        #region IDisposable

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    ArrayPool<T>.Shared.Return(_buffer.ToArray());
                    _buffer = Memory<T>.Empty;
                    _position = 0;
                }
            }

            disposedValue = true;
        }

        #endregion IDisposable
    }
}