package cn.al.tempcode.leetcode;

import java.util.Stack;

public class Solution {
    public int largestRectangleArea(int[] heights) {
        //heights[i] 、 height[i-1] 、maxValueHeight、
        int result = Integer.MIN_VALUE;
        int[] l = new int[heights.length];
        int[] r = new int[heights.length];
        Stack<int[]> stack = new Stack<int[]>();
        for(int i = 0; i < heights.length; i++){
            if(stack.isEmpty() || stack.peek()[0] < heights[i]){
                l[i] = i;
                stack.push(new int[]{heights[i],i});
            }else {
                int[] temp = new int[]{heights[i],i};
                while(!stack.isEmpty() && stack.peek()[0] >= heights[i]){
                    int[] t = stack.pop();
                    l[i] = t[1];
                    if(t[0] == heights[i]){
                        temp = t;
                    }
                }
                stack.push(temp);
            }
        }
        stack.clear();
        for(int i = heights.length - 1; i >= 0; i--){
            if(stack.isEmpty() || stack.peek()[0] < heights[i]){
                l[i] = i;
                stack.push(new int[]{heights[i],i});
            }else {
                int[] temp = new int[]{heights[i],i};
                while(!stack.isEmpty() && stack.peek()[0] >= heights[i]){
                    int[] t = stack.pop();
                    l[i] = t[1];
                    if(t[0] == heights[i]){
                        temp = t;
                    }
                }
                stack.push(temp);
            }
        }
        for(int i = 0; i < heights.length; i++){
            result = Math.max(result,heights[i] * (r[i] - l[i] + 1));
        }
        return result;

    }

    public static void main(String[] args) {
        Solution solution = new Solution();
        solution.largestRectangleArea(new int[]{9999,9999,9999,9999});
    }
}